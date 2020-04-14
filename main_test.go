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

	"github.com/google/uuid"
)

func TestGenerate(t *testing.T) {
	uuid.SetRand(rand.New(rand.NewSource(1)))
	in := configInput{
		xdsServerUri:     "example.com:443",
		gcpProjectNumber: 123456789012345,
		vpcNetworkName:   "thedefault",
		ip:               "10.9.8.7",
		zone:             "uscentral-5",
	}
	expected := `{
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
}`
	out, err := generate(in)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if expected != string(out) {
		t.Fatalf("\nexpected:\n%v\n----------------\ngot:\n%v",
			expected, string(out))
	}
}

func TestGetZone(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHttp(server)
	expected := "us-central5-c"
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/instance/zone",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("projects/123456789012345/zones/us-central5-c"))
		})
	actual, err := getZone()
	if err != nil {
		t.Fatalf("expected no error, got :%v", err)
	}
	if expected != actual {
		t.Fatalf("expected %v, got: %v", expected, actual)
	}
}

func TestGetProjectId(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	overrideHttp(server)
	expected := int64(123456789012345)
	http.HandleFunc("metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				http.Error(w, "Missing Metadata-Flavor", 403)
				return
			}
			w.Write([]byte("123456789012345"))
		})
	actual, err := getProjectId()
	if err != nil {
		t.Fatalf("expected no error, got :%v", err)
	}
	if expected != actual {
		t.Fatalf("expected %v, got: %v", expected, actual)
	}
}

func overrideHttp(s *httptest.Server) {
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		},
	}
}
