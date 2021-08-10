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
	"errors"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		desc       string
		input      configInput
		wantOutput string
	}{
		{
			desc: "happy case with v3 config by default",
			input: configInput{
				xdsServerUri:      "example.com:443",
				gcpProjectNumber:  123456789012345,
				vpcNetworkName:    "thedefault",
				ip:                "10.9.8.7",
				zone:              "uscentral-5",
				metadataLabels:    map[string]string{"k1": "v1", "k2": "v2"},
				includeV3Features: true,
			},
			wantOutput: `{
  "xds_servers": [
    {
      "server_uri": "example.com:443",
      "channel_creds": [
        {
          "type": "google_default"
        }
      ],
      "server_features": [
        "xds_v3"
      ]
    }
  ],
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/9566c74d-1003-4c4d-bbbb-0407d1e2c649",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": "123456789012345",
      "TRAFFICDIRECTOR_NETWORK_NAME": "thedefault",
      "k1": "v1",
      "k2": "v2"
    },
    "locality": {
      "zone": "uscentral-5"
    }
  }
}`,
		},
		{
			desc: "happy case with v2 config",
			input: configInput{
				xdsServerUri:      "example.com:443",
				gcpProjectNumber:  123456789012345,
				vpcNetworkName:    "thedefault",
				ip:                "10.9.8.7",
				zone:              "uscentral-5",
				includeV3Features: false,
			},
			wantOutput: `{
  "xds_servers": [
    {
      "server_uri": "example.com:443",
      "channel_creds": [
        {
          "type": "google_default"
        }
      ]
    }
  ],
  "node": {
    "id": "52fdfc07-2182-454f-963f-5f0f9a621d72~10.9.8.7",
    "cluster": "cluster",
    "metadata": {
      "TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": "123456789012345",
      "TRAFFICDIRECTOR_NETWORK_NAME": "thedefault"
    },
    "locality": {
      "zone": "uscentral-5"
    }
  }
}`,
		},
		{
			desc: "happy case with security config",
			input: configInput{
				xdsServerUri:       "example.com:443",
				gcpProjectNumber:   123456789012345,
				vpcNetworkName:     "thedefault",
				ip:                 "10.9.8.7",
				zone:               "uscentral-5",
				includeV3Features:  true,
				includePSMSecurity: true,
				secretsDir:         "/secrets/dir/",
			},
			wantOutput: `{
  "xds_servers": [
    {
      "server_uri": "example.com:443",
      "channel_creds": [
        {
          "type": "google_default"
        }
      ],
      "server_features": [
        "xds_v3"
      ]
    }
  ],
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/9566c74d-1003-4c4d-bbbb-0407d1e2c649",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": "123456789012345",
      "TRAFFICDIRECTOR_NETWORK_NAME": "thedefault"
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "/secrets/dir/certificates.pem",
        "private_key_file": "/secrets/dir/private_key.pem",
        "ca_certificate_file": "/secrets/dir/ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "happy case with deployment info",
			input: configInput{
				xdsServerUri:      "example.com:443",
				gcpProjectNumber:  123456789012345,
				vpcNetworkName:    "thedefault",
				ip:                "10.9.8.7",
				zone:              "uscentral-5",
				includeV3Features: true,
				deploymentInfo: map[string]string{
					"GCP-ZONE":      "uscentral-5",
					"GKE-CLUSTER":   "test-gke-cluster",
					"GKE-NAMESPACE": "test-gke-namespace",
					"GKE-POD":       "test-gke-pod",
					"INSTANCE-IP":   "10.9.8.7",
					"GKE-VM":        "test-gce-vm",
				},
			},
			wantOutput: `{
  "xds_servers": [
    {
      "server_uri": "example.com:443",
      "channel_creds": [
        {
          "type": "google_default"
        }
      ],
      "server_features": [
        "xds_v3"
      ]
    }
  ],
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/9566c74d-1003-4c4d-bbbb-0407d1e2c649",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFICDIRECTOR_GCP_PROJECT_NUMBER": "123456789012345",
      "TRAFFICDIRECTOR_NETWORK_NAME": "thedefault",
      "TRAFFIC_DIRECTOR_CLIENT_ENVIRONMENT": {
        "GCP-ZONE": "uscentral-5",
        "GKE-CLUSTER": "test-gke-cluster",
        "GKE-NAMESPACE": "test-gke-namespace",
        "GKE-POD": "test-gke-pod",
        "GKE-VM": "test-gce-vm",
        "INSTANCE-IP": "10.9.8.7"
      }
    },
    "locality": {
      "zone": "uscentral-5"
    }
  }
}`,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			uuid.SetRand(rand.New(rand.NewSource(1)))

			gotOutput, err := generate(test.input)
			if err != nil {
				t.Fatalf("generate(%+v) failed: %v", test.input, err)
			}
			if diff := cmp.Diff(test.wantOutput, string(gotOutput)); diff != "" {
				t.Fatalf("generate(%+v) returned output does not match expected (-want +got):\n%s", test.input, diff)
			}
		})
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

func TestGetClusterName(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHTTP(server)
	want := "test-cluster"
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("test-cluster"))
		})
	if got := getClusterName(); got != want {
		t.Fatalf("getClusterName() = %s, want: %s", got, want)
	}
}

func TestGetPodName(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T)
		want  string
	}{
		{
			name: "no-env-var-no-hostname-file",
			setup: func(t *testing.T) {
				if err := os.Setenv("HOSTNAME", ""); err != nil {
					t.Fatalf("failed to set env var HOSTNAME: %v", err)
				}
				readHostNameFile = func() ([]byte, error) { return nil, errors.New("failed to read hostname file") }
			},
			want: "",
		},
		{
			name: "no-env-var-valid-hostname-file-contents",
			setup: func(t *testing.T) {
				if err := os.Setenv("HOSTNAME", ""); err != nil {
					t.Fatalf("failed to set env var HOSTNAME: %v", err)
				}
				readHostNameFile = func() ([]byte, error) { return []byte("test-hostname1"), nil }
			},
			want: "test-hostname1",
		},
		{
			name: "valid-env-var",
			setup: func(t *testing.T) {
				if err := os.Setenv("HOSTNAME", "test-hostname2"); err != nil {
					t.Fatalf("failed to set env var HOSTNAME: %v", err)
				}
				// To ensure that a valid env var is preferred over reading the file.
				readHostNameFile = func() ([]byte, error) { return nil, errors.New("failed to read hostname file") }
			},
			want: "test-hostname2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldHostNameEnvVar := os.Getenv("HOSTNAME")
			oldReadHostNameFile := readHostNameFile
			defer func() {
				os.Setenv("HOSTNAME", oldHostNameEnvVar)
				readHostNameFile = oldReadHostNameFile
			}()

			test.setup(t)
			if got := getPodName(); got != test.want {
				t.Fatalf("getPodName() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGetVMName(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHTTP(server)
	want := "test-vm"
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/name",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("test-vm"))
		})
	if got := getVMName(); got != want {
		t.Fatalf("getVMName() = %s, want: %s", got, want)
	}
}

func overrideHTTP(s *httptest.Server) {
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
	}
}
