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

package csm_namer

import (
	"crypto/sha256"
	"strconv"
)

// lookup table to maintain entropy when converting bytes to string.
var table []string

func init() {
	for i := 0; i < 10; i++ {
		table = append(table, strconv.Itoa(i))
	}
	for i := 0; i < 26; i++ {
		table = append(table, string('a'+rune(i)))
	}
}

// Hash creates a content hash string of length n of s utilizing sha256.
// Note that 256 is not evenly divisible by 36, so the first four elements
// will be slightly more likely (3.125% chance) than the rest (2.734375% chance).
// This results in a per-character chance of collision of
// (4 * ((8/256)^2) + (36-4) * ((7/256)^2)) instead of (1 / 36).
// For an 8 character hash string (used for cluster UID and suffix hash), this
// comes out to 3.600e-13 instead of 3.545e-13, which is a negligibly larger
// chance of collision.
func Hash(s string, n int) string {
	var h string
	bytes := sha256.Sum256(([]byte)(s))
	for i := 0; i < n && i < len(bytes); i++ {
		idx := int(bytes[i]) % len(table)
		h += table[idx]
	}
	return h
}

// TrimFieldsEvenly trims the fields evenly and keeps the total length <= max.
// Truncation is spread in ratio with their original length, meaning smaller
// fields will be truncated less than longer ones.
func TrimFieldsEvenly(max int, fields ...string) []string {
	if max <= 0 {
		return fields
	}
	total := 0
	for _, s := range fields {
		total += len(s)
	}
	if total <= max {
		return fields
	}

	// Distribute truncation evenly among the fields.
	excess := total - max
	remaining := max
	var lengths []int
	for _, s := range fields {
		// Scale truncation to shorten longer fields more than ones that are already
		// short.
		l := len(s) - len(s)*excess/total - 1
		lengths = append(lengths, l)
		remaining -= l
	}
	// Add fractional space that was rounded down.
	for i := 0; i < remaining; i++ {
		lengths[i]++
	}

	var ret []string
	for i, l := range lengths {
		ret = append(ret, fields[i][:l])
	}

	return ret
}
