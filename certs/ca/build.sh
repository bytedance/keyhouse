#!/bin/bash
rm -rf private
mkdir private
cd private
cfssl gencert -initca ../ca-csr.json | cfssljson -bare ca -
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=../ca-config.json -profile=server ../server.json | cfssljson -bare server
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=../ca-config.json -profile=client ../client.json | cfssljson -bare client
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=../ca-config.json -profile=peer ../etcd.json | cfssljson -bare etcd
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=../ca-config.json -profile=client ../server_internal.json | cfssljson -bare server_internal
openssl pkcs8 -topk8 -nocrypt -in ./client-key.pem -out ./client-key_pkcs8.pem
openssl pkcs8 -topk8 -nocrypt -in ./server-key.pem -out ./server-key_pkcs8.pem
openssl pkcs8 -topk8 -nocrypt -in ./server_internal-key.pem -out ./server_internal-key_pkcs8.pem
openssl pkcs8 -topk8 -nocrypt -in ./etcd-key.pem -out ./etcd-key_pkcs8.pem