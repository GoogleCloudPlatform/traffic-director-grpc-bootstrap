// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary main generates the xDS bootstrap configuration necessary for gRPC
// applications to connect to and use Traffic Director as their xDS control
// plane.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"td-grpc-bootstrap/csmnamer"

	"github.com/google/uuid"
)

var (
	xdsServerURI               = flag.String("xds-server-uri", "trafficdirector.googleapis.com:443", "override of server uri, for testing")
	outputName                 = flag.String("output", "-", "output file name")
	gcpProjectNumber           = flag.Int64("gcp-project-number", 0, "the gcp project number. If unknown, can be found via 'gcloud projects list'")
	vpcNetworkName             = flag.String("vpc-network-name", "default", "VPC network name")
	localityZone               = flag.String("locality-zone", "", "the locality zone to use, instead of retrieving it from the metadata server. Useful when not running on GCP and/or for testing")
	ignoreResourceDeletion     = flag.Bool("ignore-resource-deletion-experimental", false, "assume missing resources notify operators when using Traffic Director, as in gRFC A53. This is not currently the case. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	secretsDir                 = flag.String("secrets-dir", "/var/run/secrets/workload-spiffe-credentials", "path to a directory containing TLS certificates and keys required for PSM security")
	gkeClusterName             = flag.String("gke-cluster-name", "", "GKE cluster name to use, instead of retrieving it from the metadata server.")
	gkePodName                 = flag.String("gke-pod-name-experimental", "", "GKE pod name to use, instead of reading it from $HOSTNAME or /etc/hostname file. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gkeNamespace               = flag.String("gke-namespace-experimental", "", "GKE namespace to use. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gkeLocation                = flag.String("gke-location-experimental", "", "the location (region/zone) of the GKE cluster, instead of retrieving it from the metadata server. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gceVM                      = flag.String("gce-vm-experimental", "", "GCE VM name to use, instead of reading it from the metadata server. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	configMesh                 = flag.String("config-mesh", "", "Dictates which Mesh resource to use.")
	generateMeshID             = flag.Bool("generate-mesh-id", false, "When enabled, the CSM MeshID is generated. If config-mesh flag is specified, this flag would be ignored. Location and Cluster Name would be retrieved from the metadata server unless specified via gke-location and gke-cluster-name flags respectively.")
	includeAllowedGrpcServices = flag.Bool("include-allowed-grpc-services-experimental", false, "When enabled, generates `allowed_grpc_services` map that includes current xDS Server URI. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	isTrustedXdsServer         = flag.Bool("is-trusted-xds-server-experimental", false, "Whether to include the server feature trusted_xds_server for TD. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
)

const (
	tdAuthority  = "traffic-director-global.xds.googleapis.com"
	c2pAuthority = "traffic-director-c2p.xds.googleapis.com"
)

func main() {
	nodeMetadata := make(map[string]string)
	flag.Var(newStringMapVal(&nodeMetadata), "node-metadata",
		"additional metadata of the form key=value to be included in the node configuration")

	flag.Var(flag.Lookup("secrets-dir").Value, "secrets-dir-experimental",
		"alias of secrets-dir. This flag is EXPERIMENTAL and will be removed in a later release")
	flag.Var(flag.Lookup("node-metadata").Value, "node-metadata-experimental",
		"alias of node-metadata. This flag is EXPERIMENTAL and will be removed in a later release")
	flag.Var(flag.Lookup("gke-cluster-name").Value, "gke-cluster-name-experimental",
		"alias of gke-cluster-name. This flag is EXPERIMENTAL and will be removed in a later release")
	flag.Var(flag.Lookup("generate-mesh-id").Value, "generate-mesh-id-experimental",
		"alias of generate-mesh-id. This flag is EXPERIMENTAL and will be removed in a later release")
	flag.Var(flag.Lookup("config-mesh").Value, "config-mesh-experimental",
		"alias of config-mesh. This flag is EXPERIMENTAL and will be removed in a later release")

	flag.Parse()

	if *gcpProjectNumber == 0 {
		var err error
		*gcpProjectNumber, err = getProjectID()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to determine project id: %s\n", err)
			os.Exit(1)
		}
	}

	ip, err := getHostIP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to determine host's ip: %s\n", err)
	}

	// Retrieve zone from the metadata server only if not specified in args.
	zone := *localityZone
	if zone == "" {
		zone, err = getZone()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
		}
	}

	// Generate deployment info from metadata server or from command-line
	// arguments, with the latter taking preference.
	var deploymentInfo map[string]string
	dType, err := getDeploymentType()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to determine deployment type: %s\n", err)
	}
	switch dType {
	case deploymentTypeGKE:
		cluster := *gkeClusterName
		if cluster == "" {
			cluster, err = getClusterName()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: generating deployment info: %s\n", err)
				os.Exit(1)
			}
		}
		pod := *gkePodName
		if pod == "" {
			pod = getPodName()
		}
		clusterLocation := *gkeLocation
		if clusterLocation == "" {
			clusterLocation, err = getClusterLocality()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: generating deployment info: %s\n", err)
				os.Exit(1)
			}
		}
		deploymentInfo = map[string]string{
			"GKE-CLUSTER":  cluster,
			"GKE-LOCATION": clusterLocation,
			"GCP-ZONE":     zone,
			"INSTANCE-IP":  ip,
			"GKE-POD":      pod,
		}
		if *gkeNamespace != "" {
			deploymentInfo["GKE-NAMESPACE"] = *gkeNamespace
		}
	case deploymentTypeGCE:
		vmName := *gceVM
		if vmName == "" {
			vmName = getVMName()
		}
		deploymentInfo = map[string]string{
			"GCE-VM":      vmName,
			"GCP-ZONE":    zone,
			"INSTANCE-IP": ip,
		}
	}

	meshID := *configMesh
	if *generateMeshID {
		if meshID != "" {
			fmt.Fprint(os.Stderr, "Error: --config-mesh flag cannot be specified while --generate-mesh-id is also set.\n")
			os.Exit(1)
		}

		clusterLocality := *gkeLocation
		if clusterLocality == "" {
			clusterLocality, err = getClusterLocality()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: unable to generate mesh id: %s\n", err)
				os.Exit(1)
			}
		}

		cluster := *gkeClusterName
		if cluster == "" {
			cluster, err = getClusterName()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: unable to generate mesh id: %s\n", err)
				os.Exit(1)
			}
		}

		meshNamer := csmnamer.MeshNamer{
			ClusterName: cluster,
			Location:    clusterLocality,
		}
		meshID = meshNamer.GenerateMeshId()
	}

	gitCommitHash, err := getCommitID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to determine git commit ID: %s\n", err)
		os.Exit(1)
	}

	input := configInput{
		xdsServerURI:               *xdsServerURI,
		gcpProjectNumber:           *gcpProjectNumber,
		vpcNetworkName:             *vpcNetworkName,
		ip:                         ip,
		zone:                       zone,
		ignoreResourceDeletion:     *ignoreResourceDeletion,
		secretsDir:                 *secretsDir,
		metadataLabels:             nodeMetadata,
		deploymentInfo:             deploymentInfo,
		configMesh:                 meshID,
		ipv6Capable:                isIPv6Capable(),
		gitCommitHash:              gitCommitHash,
		isTrustedXdsServer:         *isTrustedXdsServer,
		includeAllowedGrpcServices: *includeAllowedGrpcServices,
	}

	if err := validate(input); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	config, err := generate(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate config: %s\n", err)
		os.Exit(1)
	}
	var output *os.File
	if *outputName == "-" {
		output = os.Stdout
	} else {
		output, err = os.Create(*outputName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open output file: %s\n", err)
			os.Exit(1)
		}
	}
	_, err = output.Write(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %s\n", err)
		os.Exit(1)
	}
	_, err = output.Write([]byte("\n"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %s\n", err)
		os.Exit(1)
	}
	err = output.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to close config: %s\n", err)
		os.Exit(1)
	}
}

type configInput struct {
	xdsServerURI               string
	gcpProjectNumber           int64
	vpcNetworkName             string
	ip                         string
	zone                       string
	ignoreResourceDeletion     bool
	secretsDir                 string
	metadataLabels             map[string]string
	deploymentInfo             map[string]string
	configMesh                 string
	ipv6Capable                bool
	gitCommitHash              string
	isTrustedXdsServer         bool
	includeAllowedGrpcServices bool
}

func validate(in configInput) error {
	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)
	if in.configMesh != "" && !re.MatchString(in.configMesh) {
		return fmt.Errorf("config-mesh may only contain letters, numbers, and '-'. It must begin with a letter and must not exceed 64 characters in length")
	}

	return nil
}

func generate(in configInput) ([]byte, error) {
	xdsServer := server{
		ServerURI:    in.xdsServerURI,
		ChannelCreds: []creds{{Type: "google_default"}},
	}

	// Set xds_v3.
	xdsServer.ServerFeatures = append(xdsServer.ServerFeatures, "xds_v3")
	if in.isTrustedXdsServer {
		xdsServer.ServerFeatures = append(xdsServer.ServerFeatures, "trusted_xds_server")
	}

	if in.ignoreResourceDeletion {
		xdsServer.ServerFeatures = append(xdsServer.ServerFeatures, "ignore_resource_deletion")
	}

	// Setting networkIdentifier based on flags.
	networkIdentifier := in.vpcNetworkName
	if in.configMesh != "" {
		networkIdentifier = fmt.Sprintf("mesh:%s", in.configMesh)
	}

	c := &config{
		XDSServers: []server{xdsServer},
		Node: &node{
			ID:      fmt.Sprintf("projects/%d/networks/%s/nodes/%s", in.gcpProjectNumber, networkIdentifier, uuid.New().String()),
			Cluster: "cluster", // unused by TD
			Locality: &locality{
				Zone: in.zone,
			},
			Metadata: map[string]any{
				"INSTANCE_IP": in.ip,
				"TRAFFICDIRECTOR_GRPC_BOOTSTRAP_GENERATOR_SHA": in.gitCommitHash,
			},
		},
		Authorities: map[string]Authority{
			tdAuthority: {
				// Listener Resource Name format for normal TD usecases looks like:
				// xdstp://<authority>/envoy.config.listener.v3.Listener/<project_number>/<(network)|(mesh:mesh_name)>/id
				ClientListenerResourceNameTemplate: fmt.Sprintf("xdstp://%s/envoy.config.listener.v3.Listener/%d/%s/%%s", tdAuthority, in.gcpProjectNumber, networkIdentifier),
			},
			c2pAuthority: {
				// In the case of DirectPath, it is safe to assume that the operator is notified of missing resources.
				// In other words, "ignore_resource_deletion" server_features is always set.
				XDSServers: []server{{
					ServerURI:      "dns:///directpath-pa.googleapis.com",
					ChannelCreds:   []creds{{Type: "google_default"}},
					ServerFeatures: []string{"xds_v3", "ignore_resource_deletion"},
				}},
				ClientListenerResourceNameTemplate: fmt.Sprintf("xdstp://%s/envoy.config.listener.v3.Listener/%%s", c2pAuthority),
			},
		},
		ClientDefaultListenerResourceNameTemplate: fmt.Sprintf("xdstp://%s/envoy.config.listener.v3.Listener/%d/%s/%%s", tdAuthority, in.gcpProjectNumber, networkIdentifier),
	}

	for k, v := range in.metadataLabels {
		c.Node.Metadata[k] = v
	}

	// For PSM Security.
	c.CertificateProviders = map[string]certificateProviderConfig{
		"google_cloud_private_spiffe": {
			PluginName: "file_watcher",
			Config: privateSPIFFEConfig{
				CertificateFile:   path.Join(in.secretsDir, "certificates.pem"),
				PrivateKeyFile:    path.Join(in.secretsDir, "private_key.pem"),
				CACertificateFile: path.Join(in.secretsDir, "ca_certificates.pem"),
				// The file_watcher plugin will parse this a Duration proto, but it is totally
				// fine to just emit a string here.
				RefreshInterval: "600s",
			},
		},
	}

	// For Rate Limiting
	if in.includeAllowedGrpcServices {
		c.AllowedGrpcServices = map[string]allowedGrpcServiceConfig{
			getQualifiedXDSURI(in.xdsServerURI): {
				ChannelCreds: []creds{{Type: "google_default"}},
			},
		}
	}

	c.ServerListenerResourceNameTemplate = "grpc/server?xds.resource.listening_address=%s"
	if in.deploymentInfo != nil {
		c.Node.Metadata["TRAFFIC_DIRECTOR_CLIENT_ENVIRONMENT"] = in.deploymentInfo
	}

	if in.ipv6Capable {
		c.Node.Metadata["TRAFFICDIRECTOR_DIRECTPATH_C2P_IPV6_CAPABLE"] = true
	}

	return json.MarshalIndent(c, "", "  ")
}

func getHostIP() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for hostname: %s", hostname)
	}
	return addrs[0], nil
}

func getZone() (string, error) {
	qualifiedZone, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/zone")
	if err != nil {
		return "", fmt.Errorf("failed to determine zone: could not discover instance zone: %w", err)
	}
	i := bytes.LastIndexByte(qualifiedZone, '/')
	if i == -1 {
		return "", fmt.Errorf("failed to determine zone: could not parse zone from metadata server: %s", qualifiedZone)
	}
	return string(qualifiedZone[i+1:]), nil
}

func getProjectID() (int64, error) {
	projectIDBytes, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id")
	if err != nil {
		return 0, fmt.Errorf("could not discover project id: %w", err)
	}
	projectID, err := strconv.ParseInt(string(projectIDBytes), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse project id from metadata server: %w", err)
	}
	return projectID, nil
}

func getClusterName() (string, error) {
	cluster, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name")
	if err != nil {
		return "", fmt.Errorf("failed to determine GKE cluster name: %s", err)
	}
	return string(cluster), nil
}

func getClusterLocality() (string, error) {
	locality, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-location")
	if err != nil {
		return "", fmt.Errorf("failed to determine GKE cluster locality: %s", err)
	}
	return string(locality), nil
}

func getPodName() string {
	pod, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not discover GKE pod name: %v", err)
	}
	return pod
}

func getVMName() string {
	vm, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/name")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not discover GCE VM name: %v", err)
		return ""
	}
	return string(vm)
}

// isIPv6Capable returns true if the VM is configured with an IPv6 address.
// This will contact the metadata server to retrieve this information.
func isIPv6Capable() bool {
	_, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ipv6s")
	return err == nil
}

func getFromMetadata(urlStr string) ([]byte, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req := &http.Request{
		Method: "GET",
		URL:    parsedURL,
		Header: http.Header{
			"Metadata-Flavor": {"Google"},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed communicating with metadata server: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed reading from metadata server: %w", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("metadata server returned status code %d for url %q", code, parsedURL)
	}
	return body, nil
}

func getQualifiedXDSURI(serverURI string) string {
	if strings.HasPrefix(serverURI, "dns:///") {
		return serverURI
	}
	return "dns:///" + serverURI
}

type config struct {
	XDSServers                                []server                             `json:"xds_servers,omitempty"`
	Authorities                               map[string]Authority                 `json:"authorities,omitempty"`
	Node                                      *node                                `json:"node,omitempty"`
	CertificateProviders                      map[string]certificateProviderConfig `json:"certificate_providers,omitempty"`
	AllowedGrpcServices                       map[string]allowedGrpcServiceConfig  `json:"allowed_grpc_services,omitempty"`
	ServerListenerResourceNameTemplate        string                               `json:"server_listener_resource_name_template,omitempty"`
	ClientDefaultListenerResourceNameTemplate string                               `json:"client_default_listener_resource_name_template,omitempty"`
}

type server struct {
	ServerURI      string   `json:"server_uri,omitempty"`
	ChannelCreds   []creds  `json:"channel_creds,omitempty"`
	ServerFeatures []string `json:"server_features,omitempty"`
}

// Authority is the configuration corresponding to an authority name in the map.
//
// For more details, see:
// https://github.com/grpc/proposal/blob/master/A47-xds-federation.md#bootstrap-config-changes
type Authority struct {
	XDSServers                         []server `json:"xds_servers,omitempty"`
	ClientListenerResourceNameTemplate string   `json:"client_listener_resource_name_template,omitempty"`
}

type creds struct {
	Type   string `json:"type,omitempty"`
	Config any    `json:"config,omitempty"`
}

type node struct {
	ID           string         `json:"id,omitempty"`
	Cluster      string         `json:"cluster,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Locality     *locality      `json:"locality,omitempty"`
	BuildVersion string         `json:"build_version,omitempty"`
}

type locality struct {
	Region  string `json:"region,omitempty"`
	Zone    string `json:"zone,omitempty"`
	SubZone string `json:"sub_zone,omitempty"`
}

type certificateProviderConfig struct {
	PluginName string `json:"plugin_name,omitempty"`
	Config     any    `json:"config,omitempty"`
}

type privateSPIFFEConfig struct {
	CertificateFile   string `json:"certificate_file,omitempty"`
	PrivateKeyFile    string `json:"private_key_file,omitempty"`
	CACertificateFile string `json:"ca_certificate_file,omitempty"`
	RefreshInterval   string `json:"refresh_interval,omitempty"`
}

type allowedGrpcServiceConfig struct {
	ChannelCreds []creds `json:"channel_creds,omitempty"`
}
