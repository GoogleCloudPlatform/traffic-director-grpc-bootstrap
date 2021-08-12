// Copyright 2021 Google LLC
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
	"net/http"
	"net/url"
	"time"
)

type deploymentType int

const (
	deploymentTypeUnknown deploymentType = iota
	deploymentTypeGKE
	deploymentTypeGCE
)

// getDeploymentType tries to talk the metadata server at
// http://metadata.google.internal and uses a response header with key "Server"
// to determine the deployment type.
func getDeploymentType() deploymentType {
	parsedUrl, err := url.Parse("http://metadata.google.internal")
	if err != nil {
		return deploymentTypeUnknown
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req := &http.Request{
		Method: "GET",
		URL:    parsedUrl,
		Header: http.Header{"Metadata-Flavor": {"Google"}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return deploymentTypeUnknown
	}
	resp.Body.Close()

	// Read the "Server" header to determine the deployment type.
	vals := resp.Header.Values("Server")
	for _, val := range vals {
		switch val {
		case "GKE Metadata Server":
			return deploymentTypeGKE
		case "Metadata Server for VM":
			return deploymentTypeGCE
		}
	}
	return deploymentTypeUnknown
}
