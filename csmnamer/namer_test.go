// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// DO NOT EDIT: This code is a subset of services_platform/thetis/gateway/core/v1alpha2/common/appnettranslator/gsm/namer_test.go
// and should not be modified to maintain functional consistency.

package csmnamer

import (
	"strconv"
	"strings"
	"testing"
)

func longString(n int) string {
	var ret string
	for i := 0; i < n; i++ {
		ret += strconv.Itoa(i % 10)
	}
	return ret
}

func manyComponents(n int) []string {
	var ret []string
	for i := 0; i < n; i++ {
		ret = append(ret, strconv.Itoa(i))
	}
	return ret
}

func TestReadableResourceName(t *testing.T) {
	cases := []struct {
		desc       string
		components []string
	}{
		{
			desc:       "no-component",
			components: []string{},
		},
		{
			desc:       "single-component",
			components: []string{"default"},
		},
		{
			desc:       "multiple-components",
			components: []string{"default", "my-app-net-mesh"},
		},
		{
			desc:       "multiple-components-with-invalid-char",
			components: []string{"default", "my-app-net-mesh", "1.2.3.4??"},
		},
		{
			desc:       "multiple-components-with-invalid-char",
			components: []string{"default", "my-app-net-mesh", "example.com"},
		},
		{
			desc:       "too-many-components",
			components: manyComponents(resourceNameMaxLen),
		},
		{
			desc:       "long-components",
			components: []string{"default", longString(resourceNameMaxLen), "80"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := readableResourceName(tc.components...)
			if len(got) > resourceNameMaxLen {
				t.Errorf("readableResourceName(): got resource name of length %d, want <= %d", len(got), resourceNameMaxLen)
			}
			subs := strings.Split(got, "-")
			gotHashLen := len(subs[len(subs)-1])
			if gotHashLen != nHashLen {
				t.Errorf("readableResourceName(): got suffix hash of length %d, want %d", gotHashLen, nHashLen)
			}
			gotPrefix := subs[0]
			if gotPrefix != csmMeshPrefix {
				t.Errorf("readableResourceName(): got prefix %s, want %s", gotPrefix, csmMeshPrefix)
			}
		})
	}
}

func TestGenerateMeshId(t *testing.T) {
	cases := []struct {
		desc        string
		clusterName string
		location    string
		want        string
	}{
		{
			desc:        "no-error",
			location:    "us-central1-a",
			clusterName: "test-cluster",
			want:        "gsmmesh-4g63-test-cluster-us-central1-a-4g63fl4kjz0z",
		},
		{
			desc:        "longest-everything-and-still-no-error",
			location:    "us-northeast1-a",
			clusterName: "test-cluster-test-cluster-test-clusterss",
			want:        "gsmmesh-l5lo-test-cluster-test-cluster-t-us-northe-l5loax1rjdik",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			namer := MeshNamer{
				ClusterName: tc.clusterName,
				Location:    tc.location,
			}
			if got := namer.GenerateMeshId(); got != tc.want {
				t.Fatalf("Got name %q, want %q", got, tc.want)
			}
		})
	}
}
