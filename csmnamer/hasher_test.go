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

// DO NOT EDIT: This is a sync of services_platform/thetis/common/gke_net/naming_test.go
// and should not be modified to maintain functional consistency.

package csmnamer

import "testing"

func TestTrimFieldsEvenly(t *testing.T) {
	longString := "01234567890123456789012345678901234567890123456789"
	cases := []struct {
		desc   string
		fields []string
		want   []string
		max    int
	}{
		{
			desc:   "no-change",
			fields: []string{longString},
			want:   []string{longString},
			max:    100,
		},
		{
			desc:   "equal-to-max-and-no-change",
			fields: []string{longString, longString},
			want:   []string{longString, longString},
			max:    100,
		},
		{
			desc:   "equally-trimmed-to-half",
			fields: []string{longString, longString},
			want:   []string{longString[:25], longString[:25]},
			max:    50,
		},
		{
			desc:   "trimmed-to-only-10",
			fields: []string{longString, longString, longString},
			want:   []string{longString[:4], longString[:3], longString[:3]},
			max:    10,
		},
		{
			desc:   "trimmed-to-only-3",
			fields: []string{longString, longString, longString},
			want:   []string{longString[:1], longString[:1], longString[:1]},
			max:    3,
		},
		{
			desc:   "one-long-field-with-one-short-field",
			fields: []string{longString, longString[:10]},
			want:   []string{"01234567890123456", "012"},
			max:    20,
		},
		{
			desc:   "one-long-field-with-one-short-field-and-trimmed-to-1",
			fields: []string{longString, longString[:1]},
			want:   []string{longString[:1], ""},
			max:    1,
		},
		{
			desc:   "one-long-field-with-one-short-field-and-trimmed-to-5",
			fields: []string{longString, longString[:1]},
			want:   []string{longString[:5], ""},
			max:    5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := TrimFieldsEvenly(tc.max, tc.fields...)
			if len(got) != len(tc.want) {
				t.Fatalf("TrimFieldsEvenly(): got length %d, want %d", len(got), len(tc.want))
			}

			totalLen := 0
			for i := range got {
				totalLen += len(got[i])
				if got[i] != tc.want[i] {
					t.Errorf("TrimFieldsEvenly(): got the %d field to be %q, want %q", i, got[i], tc.want[i])
				}
			}

			if tc.max < totalLen {
				t.Errorf("TrimFieldsEvenly(): got total length %d, want less than %d", totalLen, tc.max)
			}
		})
	}
}
