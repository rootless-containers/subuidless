# rootlesscontainers.proto

This directory contains `rootlesscontainers.proto`, which is used for preserving emulated file owner information as `user.rootlesscontainers` xattr values.

## Source

https://raw.githubusercontent.com/rootless-containers/proto/316d7ae30bc5f448f217dc11623047b0f1589e53/rootlesscontainers.proto

## Compile

```console
$ protoc-c --c_out=. rootlesscontainers.proto
```
