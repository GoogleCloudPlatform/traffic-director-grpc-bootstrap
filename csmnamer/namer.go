// Copyright 2023 Google LLC
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

// DO NOT EDIT: This code is a subset of services_platform/thetis/gateway/core/v1alpha2/common/appnettranslator/gsm/namer.go
// and should not be modified to maintain functional consistency.

package csmnamer

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// Length limit for hash created from fields that uniquely identify a GCE resource and
	// appended as a suffix to the resource name
	nHashLen = 12
	// max length of a GCE resource name.
	resourceNameMaxLen = 63
	// clusterUIDLen is the length of cluster UID, computed as a hash of ClusterName
	// prefix used for GCE resource names created by GAMMA mesh.
	clusterUIDLen = 4
	// csmMeshPrefix is the prefix override used in the CSMMesh use cases.
	csmMeshPrefix = "gsmmesh"
)

type MeshNamer struct {
	ClusterName string
	Location    string
}

func (m *MeshNamer) GenerateMeshId() string {
	return readableResourceName(m.ClusterName, m.Location)
}

// Returns a readable resource name in the following format
// {prefix}-{component#0}-{component#1}...-{hash}
// The length of the returned resource name is guarantee to be within
// resourceNameLen which is the maximum length of a GCE resource. A component
// will only be included explicitly in the resource name if it doesn't have an
// invalid character (any character that is not a letter, digit or '-').
// Components in the resource name maybe trimmed to fit the maximum length
// requirement. {hash} uniquely identifies the component set.
func readableResourceName(components ...string) string {
	// clusterHash enforces uniqueness of resources of different clusters in
	// the same project.
	clusterHash := Hash(strings.Join(components, ";"), clusterUIDLen)
	prefix := csmMeshPrefix + "-" + clusterHash
	// resourceHash enforces uniqueness of resources of the same cluster.
	resourceHash := Hash(strings.Join(components, ";"), nHashLen)
	// Ideally we explicitly include all components in the GCP resource name, so
	// it's easier to be related to the corresponding k8s resource(s). However,
	// only certain characters are allowed in a GCP resource name(e.g. a common
	// character '.' in hostnames is not allowed in GCP resource name).
	var explicitComponents []string
	for _, c := range components {
		// Only explicitly include a component in GCP resource name if all
		// characters in it are allowed. Omitting a component here is okay since
		// the resourceHash already represents the full component set.
		if allCharAllowedInResourceName(c) {
			explicitComponents = append(explicitComponents, c)
		}
	}
	// The maximum total length of components is determined by subtracting length
	// of the following substring from the maximum length of resource name:
	// * prefix
	// * separators "-". There will be len(explicitComponents) + 1 of them.
	// * hash
	componentsMaxLen := resourceNameMaxLen - len(prefix) - (len(explicitComponents) + 1) - len(resourceHash)
	// Drop components from the resource name if the allowed maximum total length
	// of them is less them the total number of components. (This happens when
	// there are too many components)
	if componentsMaxLen < len(explicitComponents) {
		return fmt.Sprintf("%s-%s", prefix, resourceHash)
	}
	// Trim components to fit the allowed maximum total length.
	trimmed := TrimFieldsEvenly(componentsMaxLen, explicitComponents...)
	return fmt.Sprintf("%s-%s-%s", prefix, strings.Join(trimmed, "-"), resourceHash)
}

func allCharAllowedInResourceName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !(unicode.IsDigit(r) || unicode.IsLetter(r) || r == '-') {
			return false
		}
	}
	return true
}
