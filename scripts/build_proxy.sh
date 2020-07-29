#!/bin/bash

set -o nounset errexit pipefail

# Collect the API Proxy and Hosted Target (Sandbox server)
# files into build/apiproxy/ and deploy to Apigee

rm -rf build/proxies
mkdir -p build/proxies/live
mkdir -p build/proxies/sandbox
mkdir -p build/api_tests
cp -Rv proxies/. build/proxies
cp -Rv api_tests/. build/api_tests
