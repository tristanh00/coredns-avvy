#!/bin/bash
set -e

SRCDIR=`pwd`
BUILDDIR=`pwd`/build

mkdir -p ${BUILDDIR} 2>/dev/null
cd ${BUILDDIR}
echo "Cloning CoreDNS..."
git clone https://github.com/coredns/coredns.git

cd coredns
git checkout v1.8.3

echo "Patching plugin config..."
ed plugin.cfg <<EOED
/rewrite:rewrite
a
ens:github.com/tristanh00/coredns-avvy
.
w
q
EOED

# Add our module to coredns.
echo "Patching GO modules..."
ed go.mod <<EOED
a
replace github.com/tristanh00/coredns-avvy => ../..
.
/^)
-1
a
	github.com/tristanh00/coredns-avvy v1.0.0
.
w
q
EOED

go get github.com/tristanh00/coredns-avvy@v1.0.0
go get
go mod download

echo "Building..."
make SHELL='sh -x' CGO_ENABLED=1 coredns

cp coredns ${SRCDIR}
chmod -R 755 .git
cd ${SRCDIR}
rm -r ${BUILDDIR}
