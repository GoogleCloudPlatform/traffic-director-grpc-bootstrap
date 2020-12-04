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
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// stringMapVal implements the flag.Value interface and supports passing key
// value pairs multiple times on the command line.
type stringMapVal map[string]string

func newStringMapVal(m *map[string]string) *stringMapVal {
	return (*stringMapVal)(m)
}

func (s *stringMapVal) Set(val string) error {
	parts := strings.SplitN(val, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("flag value %q is not formatted as key=value", val)
	}
	(*s)[parts[0]] = parts[1]
	return nil
}

func (s *stringMapVal) String() string {
	keys := make([]string, 0, len(*s))
	for key := range *s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for i, key := range keys {
		if i > 0 {
			b.WriteRune(',')
		}
		b.WriteString(key)
		b.WriteRune('=')
		b.WriteString((*s)[key])
	}
	return b.String()
}

func (s *stringMapVal) Get() interface{} {
	return map[string]string(*s)
}
