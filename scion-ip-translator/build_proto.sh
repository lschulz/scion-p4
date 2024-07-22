#!/bin/sh

python3 -m grpc_tools.protoc --python_out=. --pyi_out=. --grpc_python_out=. \
    -I controller controller/proto/daemon/v1/daemon.proto

python3 -m grpc_tools.protoc --python_out=. --pyi_out=. --grpc_python_out=. \
    -I controller controller/proto/drkey/v1/drkey.proto
