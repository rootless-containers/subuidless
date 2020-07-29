# OCI Seccomp Receiver for running Rootless Containers without `/etc/subuid` and `/etc/subgid`

`subuidless` is an implementaion of OCI Seccomp Receiver for running Rootless Containers without `/etc/subuid` and `/etc/subgid`.

`subuidlesss` emulates ID-related system calls using Seccomp User Notification and XAttrs.

Unlike similar projects such as [runROOTLESS (PRoot)](https://github.com/rootless-containers/runrootless) and [remainroot](https://github.com/cyphar/remainroot), `subuidless` can minimize the overhead of system call hooking, as `subuidless` does not use ptrace.

## Status

Early POC. Do not use.

## Why do we need subuidless?
* It is hard to configure `/etc/subuid` and `/etc/subgid` in LDAP environments
* Some container images may require strange UIDs/GIDs that are out of the typical `/etc/subuid` and `/etc/subgid` configuration. The typical configuration only allows 65,536 IDs to be available in the container.

## Goals and non-goals
Goals:
* Simplicity
* Minimal overhead

Non-goals:
* Provide security boundry across emulated IDs

## Requirements
* crun with https://github.com/containers/crun/pull/438
* libseccomp >= v2.5.0
* libprotobuf-c

**Note**: libseccomp >= v2.5.0 is not available as a dpkg/rpm package in most distros as of July 2020.

To install libseccomp from the source onto a custom prefix (`/opt/libseccomp`):
```console
$ git clone https://github.com/seccomp/libseccomp.git
$ cd libseccomp
$ git checkout v2.5.0
$ ./autogen.sh
$ ./configure --prefix=/opt/seccomp && make && sudo make install
```

To install crun:
```console
$ git clone https://github.com/containers/crun.git
$ cd crun
$ hub checkout https://github.com/containers/crun/pull/438
$ ./autogen.sh
$ CFLAGS="-I/opt/libseccomp/include/" LDFLAGS="-L/opt/libseccomp/lib" ./configure && make && sudo make install
```

## Usage

Terminal 1:
```console
$ LIBSECCOMP_PREFIX=/opt/libseccomp ./make.sh
$ mkdir -p ./test/rootfs && docker create --name foo alpine && docker export foo | tar Cx ./test/rootfs && docker rm -f foo
$ ./subuidless ~/.subuidless.sock
Listening on /home/user/.subuidless.sock
...
```

Terminal 2:
```console
$ RUN_OCI_SECCOMP_RECEIVER=~/.subuidless.sock unshare -r crun run -b ./test foo
/ # cat /proc/self/uid_map
         0       1001          1
/ # touch foo
/ # chown 42:42 foo
/ # ls -ln foo
-rw-r--r--    1 42       42               0 Jul 29 12:06 foo
```

Make sure that the `chown` command succeeds without `Invalid argument` error, even though no subuid is configured in the `uid_map` file.

The UID ang GID are recorded to [the `user.rootlesscontainers` xattr](https://github.com/rootless-containers/proto) of the target file. 

## Hooked system calls
- [X] `chown`
- [ ] `fchown`
- [ ] `fchownat`
- [ ] `lchown`

- [X] `lstat`
- ...

TODO:
```
https://github.com/rootless-containers/PRoot/blob/081bb63955eb4378e53cf4d0eb0ed0d3222bf66e/src/extension/fake_id0/fake_id0.c#L141-L205
https://github.com/cyphar/remainroot/blob/master/src/ptrace/generic-shims.c
```
