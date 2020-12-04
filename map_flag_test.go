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
	"flag"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestStringMapVal(t *testing.T) {
	tests := []struct {
		desc      string
		keyValues []string
		wantMap   map[string]string
		wantErr   bool
	}{
		{
			desc:      "badly formatted",
			keyValues: []string{"key:val"},
			wantErr:   true,
		},
		{
			desc:      "happy single",
			keyValues: []string{"key=val"},
			wantMap:   map[string]string{"key": "val"},
		},
		{
			desc:      "happy multiple",
			keyValues: []string{"key1=val1", "key2=val2"},
			wantMap:   map[string]string{"key1": "val1", "key2": "val2"},
		},
		{
			desc:      "happy with = in val",
			keyValues: []string{"key=val=1"},
			wantMap:   map[string]string{"key": "val=1"},
		},
		{
			desc:      "happy with empty val",
			keyValues: []string{"key="},
			wantMap:   map[string]string{"key": ""},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sm := make(map[string]string)
			fs := flag.NewFlagSet("testStringMapVal", flag.ContinueOnError)
			fs.Var(newStringMapVal(&sm), "metadata", "")

			var cmdLine []string
			for _, kv := range test.keyValues {
				cmdLine = append(cmdLine, "-metadata", kv)
			}
			if err := fs.Parse(cmdLine); (err != nil) != test.wantErr {
				t.Fatalf("Parse(%v) returned err: %v, wantErr: %v", cmdLine, err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if !cmp.Equal(sm, test.wantMap, cmpopts.EquateEmpty()) {
				t.Fatalf("stringMap after Parse(%v) is: %v, want: %v", cmdLine, sm, test.wantMap)
			}
		})
	}
}
