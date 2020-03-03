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
	"strconv"
	"time"

	"github.com/google/uuid"
)

var outputName = flag.String("output", "-", "output file name")
var gcpProjectNumber = flag.Int64("gcp-project-number", 0,
	"the gcp project number. If unknown, can be found via 'gcloud projects list'")
var vpcNetworkName = flag.String("vpc-network-name", "default", "VPC network name")

func main() {
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
	zone, err := getZone()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to determine zone: %s\n", err)
		zone = ""
	}
	config, err := generate(configInput{
		gcpProjectNumber: *gcpProjectNumber,
		vpcNetworkName:   *vpcNetworkName,
		ip:               ip,
		zone:             zone,
	})
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
	gcpProjectNumber int64
	vpcNetworkName   string
	ip               string
	zone             string
}

func generate(in configInput) ([]byte, error) {
	c := &config{
		XdsServers: []server{
			{
				ServerUri: "trafficdirector.googleapis.com:443",
				ChannelCreds: []creds{
					{Type: "google_default"},
				},
			},
		},
		Node: &node{
			Id:      uuid.New().String() + "~" + in.ip,
			Cluster: "cluster", // unused by TD
			Locality: &locality{
				Zone: in.zone,
			},
			Metadata: map[string]string{
				"TRAFFICDIRECTOR_NETWORK_NAME":       in.vpcNetworkName,
				"TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": strconv.FormatInt(in.gcpProjectNumber, 10),
			},
		},
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
	return body, nil
}

type config struct {
	XdsServers []server `json:"xds_servers,omitempty"`
	Node       *node    `json:"node,omitempty"`
}

type server struct {
	ServerUri    string  `json:"server_uri,omitempty"`
	ChannelCreds []creds `json:"channel_creds,omitempty"`
}

type creds struct {
	Type   string      `json:"type,omitempty"`
	Config interface{} `json:"config,omitempty"`
}

type node struct {
	Id           string      `json:"id,omitempty"`
	Cluster      string      `json:"cluster,omitempty"`
	Metadata     interface{} `json:"metadata,omitempty"`
	Locality     *locality   `json:"locality,omitempty"`
	BuildVersion string      `json:"build_version,omitempty"`
}

type locality struct {
	Region  string `json:"region,omitempty"`
	Zone    string `json:"zone,omitempty"`
	SubZone string `json:"sub_zone,omitempty"`
}
