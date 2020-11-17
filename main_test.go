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
			desc: "happy case",
			input: configInput{
				xdsServerUri:     "example.com:443",
				gcpProjectNumber: 123456789012345,
				vpcNetworkName:   "thedefault",
				ip:               "10.9.8.7",
				zone:             "uscentral-5",
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
			desc: "happy case with v3 config",
			input: configInput{
				xdsServerUri:      "example.com:443",
				gcpProjectNumber:  123456789012345,
				vpcNetworkName:    "thedefault",
				ip:                "10.9.8.7",
				zone:              "uscentral-5",
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
  }
}`,
		},
		{
			desc: "happy case with v3 and security config",
			input: configInput{
				xdsServerUri:       "example.com:443",
				gcpProjectNumber:   123456789012345,
				vpcNetworkName:     "thedefault",
				ip:                 "10.9.8.7",
				zone:               "uscentral-5",
				includeV3Features:  true,
				includePSMSecurity: true,
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
        "certificate_file": "/var/run/gke-spiffe/certs/certificates.pem",
        "private_key_file": "/var/run/gke-spiffe/certs/private_key.pem",
        "ca_certificate_file": "/var/run/gke-spiffe/certs/ca_certificates.pem",
        "refresh_interval": "600s"
      }
    }
  },
  "grpc_server_resource_name_id": "grpc/server"
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

func overrideHTTP(s *httptest.Server) {
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
	}
}
