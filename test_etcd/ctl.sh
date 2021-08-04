#!/bin/bash
etcdctl --cert-file=../certs/server_internal/cert.pem --key-file=../certs/server_internal/key.pem --client-cert-auth=true --trusted-ca-file=../certs/server_internal/ca.crt "$@"
