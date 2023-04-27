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

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	tdURI        = "trafficdirector.googleapis.com:443"
	tdAuthority  = "traffic-director-global.xds.googleapis.com"
	c2pAuthority = "traffic-director-c2p.xds.googleapis.com"
)

var (
	xdsServerUri               = flag.String("xds-server-uri", tdURI, "override of server uri, for testing")
	outputName                 = flag.String("output", "-", "output file name")
	gcpProjectNumber           = flag.Int64("gcp-project-number", 0, "the gcp project number. If unknown, can be found via 'gcloud projects list'")
	vpcNetworkName             = flag.String("vpc-network-name", "default", "VPC network name")
	localityZone               = flag.String("locality-zone", "", "the locality zone to use, instead of retrieving it from the metadata server. Useful when not running on GCP and/or for testing")
	ignoreResourceDeletion     = flag.Bool("ignore-resource-deletion-experimental", false, "assume missing resources notify operators when using Traffic Director, as in gRFC A53. This is not currently the case. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	includeV3Features          = flag.Bool("include-v3-features-experimental", true, "whether or not to generate configs which works with the xDS v3 implementation in TD. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	includePSMSecurity         = flag.Bool("include-psm-security-experimental", true, "whether or not to generate config required for PSM security. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	secretsDir                 = flag.String("secrets-dir", "/var/run/secrets/workload-spiffe-credentials", "path to a directory containing TLS certificates and keys required for PSM security")
	includeDeploymentInfo      = flag.Bool("include-deployment-info-experimental", false, "whether or not to generate config which contains deployment related information. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gkeClusterName             = flag.String("gke-cluster-name-experimental", "", "GKE cluster name to use, instead of retrieving it from the metadata server. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gkePodName                 = flag.String("gke-pod-name-experimental", "", "GKE pod name to use, instead of reading it from $HOSTNAME or /etc/hostname file. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gkeNamespace               = flag.String("gke-namespace-experimental", "", "GKE namespace to use. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	gceVM                      = flag.String("gce-vm-experimental", "", "GCE VM name to use, instead of reading it from the metadata server. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	configMesh                 = flag.String("config-mesh-experimental", "", "Dictates which Mesh resource to use. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	includeFederationSupport   = flag.Bool("include-federation-support-experimental", false, "whether or not to generate configs required for xDS Federation. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	includeDirectPathAuthority = flag.Bool("include-directpath-authority-experimental", false, "whether or not to include DirectPath TD authority for xDS Federation. Ignored if not used with include-federation-support-experimental flag. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
	// TODO: default to true when TD supports xdstp style names.
	includeXDSTPNameInLDS = flag.Bool("include-xdstp-name-in-lds-experimental", false, "whether or not to use XDSTP style name for listener resource name template. Ignored if not used with include-federation-support-experimental flag. This flag is EXPERIMENTAL and may be changed or removed in a later release.")
)

func main() {
	nodeMetadata := make(map[string]string)
	flag.Var(newStringMapVal(&nodeMetadata), "node-metadata",
		"additional metadata of the form key=value to be included in the node configuration")

	flag.Var(flag.Lookup("secrets-dir").Value, "secrets-dir-experimental",
		"alias of secrets-dir. This flag is EXPERIMENTAL and will be removed in a later release")
	flag.Var(flag.Lookup("node-metadata").Value, "node-metadata-experimental",
		"alias of node-metadata. This flag is EXPERIMENTAL and will be removed in a later release")

	flag.Parse()
	if *gcpProjectNumber == 0 {
		var err error
		*gcpProjectNumber, err = getProjectId()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to determine project id: %s\n", err)
			os.Exit(1)
		}
	}
	ip, err := getHostIp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to determine host's ip: %s\n", err)
		ip = ""
	}
	// Retrieve zone from the metadata server only if not specified in args.
	zone := *localityZone
	if zone == "" {
		zone, err = getZone()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to determine zone: %s\n", err)
			zone = ""
		}
	}

	// Generate deployment info from metadata server or from command-line
	// arguments, with the latter taking preference.
	var deploymentInfo map[string]string
	if *includeDeploymentInfo {
		dType := getDeploymentType()
		switch dType {
		case deploymentTypeGKE:
			cluster := *gkeClusterName
			if cluster == "" {
				cluster = getClusterName()
			}
			pod := *gkePodName
			if pod == "" {
				pod = getPodName()
			}
			deploymentInfo = map[string]string{
				"GKE-CLUSTER":   cluster,
				"GCP-ZONE":      zone,
				"INSTANCE-IP":   ip,
				"GKE-POD":       pod,
				"GKE-NAMESPACE": *gkeNamespace,
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
	}

	input := configInput{
		xdsServerUri:               *xdsServerUri,
		gcpProjectNumber:           *gcpProjectNumber,
		vpcNetworkName:             *vpcNetworkName,
		ip:                         ip,
		zone:                       zone,
		ignoreResourceDeletion:     *ignoreResourceDeletion,
		includeV3Features:          *includeV3Features,
		includePSMSecurity:         *includePSMSecurity,
		secretsDir:                 *secretsDir,
		metadataLabels:             nodeMetadata,
		deploymentInfo:             deploymentInfo,
		configMesh:                 *configMesh,
		includeFederationSupport:   *includeFederationSupport,
		includeDirectPathAuthority: *includeDirectPathAuthority,
		ipv6Capable:                isIPv6Capable(),
		includeXDSTPNameInLDS:      *includeXDSTPNameInLDS,
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
	xdsServerUri               string
	gcpProjectNumber           int64
	vpcNetworkName             string
	ip                         string
	zone                       string
	ignoreResourceDeletion     bool
	includeV3Features          bool
	includePSMSecurity         bool
	secretsDir                 string
	metadataLabels             map[string]string
	deploymentInfo             map[string]string
	configMesh                 string
	includeFederationSupport   bool
	includeDirectPathAuthority bool
	ipv6Capable                bool
	includeXDSTPNameInLDS      bool
}

func validate(in configInput) error {
	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)
	if in.configMesh != "" && !re.MatchString(in.configMesh) {
		return fmt.Errorf("config-mesh may only contain letters, numbers, and '-'. It must begin with a letter and must not exceed 64 characters in length")
	}

	return nil
}

func generate(in configInput) ([]byte, error) {
	c := &config{
		XdsServers: generateServerConfigsFromInputs(in.xdsServerUri, in),
		Node: &node{
			Id:      uuid.New().String() + "~" + in.ip,
			Cluster: "cluster", // unused by TD
			Locality: &locality{
				Zone: in.zone,
			},
			Metadata: map[string]interface{}{
				"TRAFFICDIRECTOR_NETWORK_NAME":       in.vpcNetworkName,
				"TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": strconv.FormatInt(in.gcpProjectNumber, 10),
			},
		},
	}

	for k, v := range in.metadataLabels {
		c.Node.Metadata[k] = v
	}
	if in.includeV3Features {
		// xDS v2 implementation in TD expects the projectNumber and networkName in
		// the metadata field while the v3 implementation expects these in the id
		// field.
		networkIdentifier := in.vpcNetworkName
		if in.configMesh != "" {
			networkIdentifier = fmt.Sprintf("mesh:%s", in.configMesh)
		}

		c.Node.Id = fmt.Sprintf("projects/%d/networks/%s/nodes/%s", in.gcpProjectNumber, networkIdentifier, uuid.New().String())
		// xDS v2 implementation in TD expects the IP address to be encoded in the
		// id field while the v3 implementation expects this in the metadata.
		c.Node.Metadata["INSTANCE_IP"] = in.ip
	}
	if in.includePSMSecurity {
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
		c.ServerListenerResourceNameTemplate = "grpc/server?xds.resource.listening_address=%s"
	}
	if in.deploymentInfo != nil {
		c.Node.Metadata["TRAFFIC_DIRECTOR_CLIENT_ENVIRONMENT"] = in.deploymentInfo
	}
	if in.includeFederationSupport {
		// Authorities with an empty server config will end up using
		// the top-level server config. For more details, see:
		// https://github.com/grpc/proposal/blob/master/A47-xds-federation.md#bootstrap-config-changes.
		c.Authorities = map[string]Authority{
			"": {},
		}

		if in.includeXDSTPNameInLDS {
			c.Authorities[tdAuthority] = Authority{
				ClientListenerResourceNameTemplate: fmt.Sprintf("xdstp://%s/envoy.config.listener.v3.Listener/%%s", tdAuthority),
			}
		}

		if in.includeDirectPathAuthority {
			c.Authorities[c2pAuthority] = Authority{
				XdsServers:                         generateServerConfigsFromInputs("dns:///directpath-pa.googleapis.com", in),
				ClientListenerResourceNameTemplate: fmt.Sprintf("xdstp://%s/envoy.config.listener.v3.Listener/%%s", c2pAuthority),
			}
			if in.ipv6Capable {
				c.Node.Metadata["TRAFFICDIRECTOR_DIRECTPATH_C2P_IPV6_CAPABLE"] = true
			}
		}
	}

	return json.MarshalIndent(c, "", "  ")
}

func getHostIp() (string, error) {
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
		return "", fmt.Errorf("could not discover instance zone: %w", err)
	}
	i := bytes.LastIndexByte(qualifiedZone, '/')
	if i == -1 {
		return "", fmt.Errorf("could not parse zone from metadata server: %s", qualifiedZone)
	}
	return string(qualifiedZone[i+1:]), nil
}

func getProjectId() (int64, error) {
	projectIdBytes, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id")
	if err != nil {
		return 0, fmt.Errorf("could not discover project id: %w", err)
	}
	projectId, err := strconv.ParseInt(string(projectIdBytes), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse project id from metadata server: %w", err)
	}
	return projectId, nil
}

func getClusterName() string {
	cluster, err := getFromMetadata("http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not discover GKE cluster name: %v", err)
		return ""
	}
	return string(cluster)
}

// For overriding in unit tests.
var readHostNameFile = func() ([]byte, error) {
	return ioutil.ReadFile("/etc/hostname")
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
	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req := &http.Request{
		Method: "GET",
		URL:    parsedUrl,
		Header: http.Header{
			"Metadata-Flavor": {"Google"},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed communicating with metadata server: %w", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed reading from metadata server: %w", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("metadata server returned status code %d for url %q", code, parsedUrl)
	}
	return body, nil
}

type config struct {
	XdsServers                         []server                             `json:"xds_servers,omitempty"`
	Authorities                        map[string]Authority                 `json:"authorities,omitempty"`
	Node                               *node                                `json:"node,omitempty"`
	CertificateProviders               map[string]certificateProviderConfig `json:"certificate_providers,omitempty"`
	ServerListenerResourceNameTemplate string                               `json:"server_listener_resource_name_template,omitempty"`
}

type server struct {
	ServerUri      string   `json:"server_uri,omitempty"`
	ChannelCreds   []creds  `json:"channel_creds,omitempty"`
	ServerFeatures []string `json:"server_features,omitempty"`
}

func generateServerConfigsFromInputs(serverUri string, in configInput) []server {
	s := server{
		ServerUri: serverUri,
		ChannelCreds: []creds{
			{Type: "google_default"},
		},
	}
	if in.includeV3Features {
		s.ServerFeatures = append(s.ServerFeatures, "xds_v3")
	}
	if in.ignoreResourceDeletion {
		s.ServerFeatures = append(s.ServerFeatures, "ignore_resource_deletion")
	}

	return []server{s}
}

// Authority is the configuration corresponding to an authority name in the map.
//
// For more details, see:
// https://github.com/grpc/proposal/blob/master/A47-xds-federation.md#bootstrap-config-changes
type Authority struct {
	XdsServers                         []server `json:"xds_servers,omitempty"`
	ClientListenerResourceNameTemplate string   `json:"client_listener_resource_name_template,omitempty"`
}

type creds struct {
	Type   string      `json:"type,omitempty"`
	Config interface{} `json:"config,omitempty"`
}

type node struct {
	Id           string                 `json:"id,omitempty"`
	Cluster      string                 `json:"cluster,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Locality     *locality              `json:"locality,omitempty"`
	BuildVersion string                 `json:"build_version,omitempty"`
}

type locality struct {
	Region  string `json:"region,omitempty"`
	Zone    string `json:"zone,omitempty"`
	SubZone string `json:"sub_zone,omitempty"`
}

type certificateProviderConfig struct {
	PluginName string      `json:"plugin_name,omitempty"`
	Config     interface{} `json:"config,omitempty"`
}

type privateSPIFFEConfig struct {
	CertificateFile   string `json:"certificate_file,omitempty"`
	PrivateKeyFile    string `json:"private_key_file,omitempty"`
	CACertificateFile string `json:"ca_certificate_file,omitempty"`
	RefreshInterval   string `json:"refresh_interval,omitempty"`
}
