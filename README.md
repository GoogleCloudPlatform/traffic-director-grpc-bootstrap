# Traffic Director gRPC Bootstrap

This repository contains sources to generate a bootstrap file for the XDS
functionality in gRPC when using GCP and Traffic Director as your control plane.

The gRPC bootstrap format is described in [gRFC A27][]. More information about
Traffic Director is available on the [Google Cloud
website](https://cloud.google.com/traffic-director/).

[gRFC A27]: https://github.com/grpc/proposal/blob/master/A27-xds-global-load-balancing.md

## Public Docker Image

Built Docker image is publicly available at Google Container Registry:
gcr.io/trafficdirector-prod/td-grpc-bootstrap

Please refer to the [GKE setup guide](https://cloud.google.com/traffic-director/docs/set-up-proxyless-gke)
for more details.

## Running unit tests

To run unit tests, run the following command:
```
go test ./... -buildvcs=true
```