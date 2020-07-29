#!/bin/bash
# FIXME: use autoconf/automake

# requires libseccomp >= v2.5.0
: ${LIBSECCOMP_PREFIX:=/opt/libseccomp}

set -eux -o pipefail
gcc -o subuidless -I${LIBSECCOMP_PREFIX}/include *.c pb/*.c ${LIBSECCOMP_PREFIX}/lib/libseccomp.a -lprotobuf-c
