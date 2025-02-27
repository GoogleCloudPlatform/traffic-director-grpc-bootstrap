// Copyright 2025 Google LLC
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
	"regexp"
	"testing"
)

func TestGetCommitId(t *testing.T) {
	commitID, err := getCommitID()
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`^[a-f0-9]{40}$`)
	if !re.MatchString(commitID) {
		t.Fatalf("getCommitId(): returned an invalid commit ID: %q. Want commit ID to be a valid SHA1 hash.", commitID)
	}
}
