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
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		desc      string
		input     configInput
		wantError string
	}{
		{
			desc: "fails when config-mesh has too many characters",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				metadataLabels:   map[string]string{"k1": "v1", "k2": "v2"},
				configMesh:       strings.Repeat("a", 65),
			},
			wantError: "config-mesh may only contain letters, numbers, and '-'. It must begin with a letter and must not exceed 64 characters in length",
		},
		{
			desc: "fails when config-mesh does not start with an alphabetic letter",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				metadataLabels:   map[string]string{"k1": "v1", "k2": "v2"},
				configMesh:       "4foo",
			},
			wantError: "config-mesh may only contain letters, numbers, and '-'. It must begin with a letter and must not exceed 64 characters in length",
		},
		{
			desc: "fails when config-mesh contains characters besides letters, numbers, and hyphens.",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				metadataLabels:   map[string]string{"k1": "v1", "k2": "v2"},
				configMesh:       "h*x8",
			},
			wantError: "config-mesh may only contain letters, numbers, and '-'. It must begin with a letter and must not exceed 64 characters in length",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			err := validate(test.input)
			if test.wantError != err.Error() {
				t.Fatalf("validate(%+v) returned output does not match expected:\nGot: \"%v\"\nWant: \"%s\"", test.input, err.Error(), test.wantError)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		desc       string
		input      configInput
		wantOutput string
	}{
		{
			desc: "happy case with v3 config by default",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				metadataLabels:   map[string]string{"k1": "v1", "k2": "v2"},
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
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "k1": "v1",
      "k2": "v2"
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "happy case with security config",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				secretsDir:       "/secrets/dir/",
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
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7"
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
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				deploymentInfo: map[string]string{
					"GCP-ZONE":      "uscentral-5",
					"GKE-CLUSTER":   "test-gke-cluster",
					"GKE-NAMESPACE": "test-gke-namespace",
					"GKE-POD":       "test-gke-pod",
					"INSTANCE-IP":   "10.9.8.7",
					"GCE-VM":        "test-gce-vm",
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
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFIC_DIRECTOR_CLIENT_ENVIRONMENT": {
        "GCE-VM": "test-gce-vm",
        "GCP-ZONE": "uscentral-5",
        "GKE-CLUSTER": "test-gke-cluster",
        "GKE-NAMESPACE": "test-gke-namespace",
        "GKE-POD": "test-gke-pod",
        "INSTANCE-IP": "10.9.8.7"
      }
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "configMesh specified",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
				deploymentInfo: map[string]string{
					"GCP-ZONE":      "uscentral-5",
					"GKE-CLUSTER":   "test-gke-cluster",
					"GKE-NAMESPACE": "test-gke-namespace",
					"GKE-POD":       "test-gke-pod",
					"INSTANCE-IP":   "10.9.8.7",
					"GCE-VM":        "test-gce-vm",
				},
				configMesh: "testmesh",
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
    "id": "projects/123456789012345/networks/mesh:testmesh/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFIC_DIRECTOR_CLIENT_ENVIRONMENT": {
        "GCE-VM": "test-gce-vm",
        "GCP-ZONE": "uscentral-5",
        "GKE-CLUSTER": "test-gke-cluster",
        "GKE-NAMESPACE": "test-gke-namespace",
        "GKE-POD": "test-gke-pod",
        "INSTANCE-IP": "10.9.8.7"
      }
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "ignore_resource_deletion and v3",
			input: configInput{
				xdsServerUri:           "example.com:443",
				gcpProjectNumber:       123456789012345,
				vpcNetworkName:         "thedefault",
				ip:                     "10.9.8.7",
				zone:                   "uscentral-5",
				ignoreResourceDeletion: true,
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
        "xds_v3",
        "ignore_resource_deletion"
      ]
    }
  ],
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7"
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "happy case with federation support of c2p authority included",
			input: configInput{
				xdsServerUri:               "example.com:443",
				gcpProjectNumber:           123456789012345,
				vpcNetworkName:             "thedefault",
				ip:                         "10.9.8.7",
				zone:                       "uscentral-5",
				includeDirectPathAuthority: true,
				ipv6Capable:                true,
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
  "authorities": {
    "traffic-director-c2p.xds.googleapis.com": {
      "xds_servers": [
        {
          "server_uri": "dns:///directpath-pa.googleapis.com",
          "channel_creds": [
            {
              "type": "google_default"
            }
          ],
          "server_features": [
            "xds_v3",
            "ignore_resource_deletion"
          ]
        }
      ],
      "client_listener_resource_name_template": "xdstp://traffic-director-c2p.xds.googleapis.com/envoy.config.listener.v3.Listener/%s"
    }
  },
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFICDIRECTOR_DIRECTPATH_C2P_IPV6_CAPABLE": true
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
}`,
		},
		{
			desc: "happy case with federation support of c2p along with regular TD using xdstp style name",
			input: configInput{
				xdsServerUri:               "trafficdirector.googleapis.com:443",
				gcpProjectNumber:           123456789012345,
				vpcNetworkName:             "thedefault",
				ip:                         "10.9.8.7",
				zone:                       "uscentral-5",
				includeDirectPathAuthority: true,
				ipv6Capable:                true,
				includeXDSTPNameInLDS:      true,
			},
			wantOutput: `{
  "xds_servers": [
    {
      "server_uri": "trafficdirector.googleapis.com:443",
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
  "authorities": {
    "traffic-director-c2p.xds.googleapis.com": {
      "xds_servers": [
        {
          "server_uri": "dns:///directpath-pa.googleapis.com",
          "channel_creds": [
            {
              "type": "google_default"
            }
          ],
          "server_features": [
            "xds_v3",
            "ignore_resource_deletion"
          ]
        }
      ],
      "client_listener_resource_name_template": "xdstp://traffic-director-c2p.xds.googleapis.com/envoy.config.listener.v3.Listener/%s"
    },
    "traffic-director-global.xds.googleapis.com": {
      "client_listener_resource_name_template": "xdstp://traffic-director-global.xds.googleapis.com/envoy.config.listener.v3.Listener/123456789012345/thedefault/%s"
    }
  },
  "node": {
    "id": "projects/123456789012345/networks/thedefault/nodes/52fdfc07-2182-454f-963f-5f0f9a621d72",
    "cluster": "cluster",
    "metadata": {
      "INSTANCE_IP": "10.9.8.7",
      "TRAFFICDIRECTOR_DIRECTPATH_C2P_IPV6_CAPABLE": true
    },
    "locality": {
      "zone": "uscentral-5"
    }
  },
  "certificate_providers": {
    "google_cloud_private_spiffe": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "certificates.pem",
        "private_key_file": "private_key.pem",
        "ca_certificate_file": "ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "server_listener_resource_name_template": "grpc/server?xds.resource.listening_address=%s"
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
	if got, _ := getClusterName(); got != want {
		t.Fatalf("getClusterName() = %s, want: %s", got, want)
	}
}

func TestGetClusterLocality(t *testing.T) {
	tests := []struct {
		desc    string
		handler func(http.ResponseWriter, *http.Request)
		want    string
		wantErr bool
	}{
		{
			desc: "zonal_succeess",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Metadata-Flavor") != "Google" {
					http.Error(w, "Missing Metadata-Flavor", http.StatusForbidden)
					return
				}
				w.Write([]byte("us-west1-a"))
			},
			want: "us-west1-a",
		},
		{
			desc: "regional_succeess",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Metadata-Flavor") != "Google" {
					http.Error(w, "Missing Metadata-Flavor", http.StatusForbidden)
					return
				}
				w.Write([]byte("us-west1"))
			},
			want: "us-west1",
		},
		{
			desc: "no_response_from_server",
			handler: func(w http.ResponseWriter, r *http.Request) {
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-locality", tt.handler)
			server := httptest.NewServer(mux)
			defer server.Close()
			overrideHTTP(server)

			got, err := getClusterLocality()
			if (err != nil) != tt.wantErr {
				t.Fatalf("getClusterLocality() returned error: %s wantErr: %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("getClusterLocality() = %s want: %s", got, tt.want)
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

func TestCheckIPv6Capable(t *testing.T) {
	tests := []struct {
		desc        string
		httpHandler func(http.ResponseWriter, *http.Request)
		wantOutput  bool
	}{
		{
			desc: "v6 enabled",
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Metadata-Flavor") != "Google" {
					http.Error(w, "Missing Metadata-Flavor", 403)
					return
				}
				w.Write([]byte("6970:7636:2061:6464:7265:7373:2062:6162"))
			},
			wantOutput: true,
		},
		{
			desc: "v6 not enabled",
			httpHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Not Found", 404)
				return
			},
			wantOutput: false,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ipv6s", test.httpHandler)
			server := httptest.NewServer(mux)
			defer server.Close()
			overrideHTTP(server)
			if got := isIPv6Capable(); got != test.wantOutput {
				t.Fatalf("isIPv6Capable() = %t, want: %t", got, test.wantOutput)
			}

		})
	}

}

func overrideHTTP(s *httptest.Server) {
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
	}
}
