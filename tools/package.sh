#!/bin/sh
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 VERSION"
  echo ""
  echo "Expected to be run from the root of the repo"
  exit 1
fi

version="$1"
mkdir "td-grpc-bootstrap-${version}/"
cp td-grpc-bootstrap "td-grpc-bootstrap-${version}/"
tar czf "td-grpc-bootstrap-${version}.tar.gz" "td-grpc-bootstrap-${version}/"
rm -r "td-grpc-bootstrap-${version}/"
