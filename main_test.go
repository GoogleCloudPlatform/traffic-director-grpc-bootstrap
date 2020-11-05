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
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGenerate2(t *testing.T) {
	origUUIString := newUUIDString
	newUUIDString = func() string { return "dummy-uuid" }
	defer func() { newUUIDString = origUUIString }()

	input := configInput{
		xdsServerUri:     "dummy-server",
		gcpProjectNumber: 666,
		vpcNetworkName:   "vpc-network-name",
		ip:               "1.2.3.4",
		zone:             "us-west1a",
	}

	// This is much easier than specifying the expected JSON config as a string
	// here since we have to be accurate with whitespace.
	wantConfig := config{
		XdsServers: []server{
			{
				ServerUri: "dummy-server",
				ChannelCreds: []creds{
					{
						Type: "google_default",
					},
				},
			},
		},
		Node: &node{
			Id:       "dummy-uuid~1.2.3.4",
			Cluster:  "cluster",
			Locality: &locality{Zone: "us-west1a"},
			Metadata: map[string]string{
				"TRAFFICDIRECTOR_NETWORK_NAME":       "vpc-network-name",
				"TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": "666",
			},
		},
		CertificateProviders: map[string]certificateProviderConfig{
			"google_cloud_private_spiffe": {
				PluginName: "file_watcher",
				Config: privateSPIFFEConfig{
					CertificateFile:   "/var/run/gke-spiffe/certs/certificates.pem",
					PrivateKeyFile:    "/var/run/gke-spiffe/certs/private_key.pem",
					CACertificateFile: "/var/run/gke-spiffe/certs/ca_certificates.pem",
					RefreshInterval:   "10m",
				},
			},
		},
	}
	wantOutput, err := json.MarshalIndent(wantConfig, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent(%+v) failed: %v", wantConfig, err)
	}

	gotOutput, err := generate(input)
	if err != nil {
		t.Fatalf("generate(%+v) failed: %v", input, err)
	}
	if diff := cmp.Diff(string(wantOutput), string(gotOutput)); diff != "" {
		t.Fatalf("generate(%+v) returned output does not match expected (-want +got):\n%s", input, diff)
	}
}
func TestGetZone(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHTTP(server)
	want := "us-central5-c"
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/zone",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("projects/123456789012345/zones/us-central5-c"))
		})
	got, err := getZone()
	if err != nil {
		t.Fatalf("want no error, got :%v", err)
	}
	if want != got {
		t.Fatalf("want %v, got: %v", want, got)
	}
}

func TestGetProjectId(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHTTP(server)
	want := int64(123456789012345)
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("123456789012345"))
		})
	got, err := getProjectId()
	if err != nil {
		t.Fatalf("want no error, got :%v", err)
	}
	if want != got {
		t.Fatalf("want %v, got: %v", want, got)
	}
}

func overrideHTTP(s *httptest.Server) {
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
	}
}
