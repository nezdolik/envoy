#!/bin/sh

set -ex

#docker build -f ci/Dockerfile-envoy-image -t envoyproxy/envoy-dev:latest .
docker build -f ci/Dockerfile-envoy-alpine -t nezdolik:envoy .
#docker build -f ci/Dockerfile-envoy-alpine-debug -t envoyproxy/envoy-alpine-debug-dev:latest .
