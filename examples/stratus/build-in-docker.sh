#!/bin/sh

[ -f docker/nim/bin/nim ] || {
  mkdir -p docker
  cd docker
  git clone https://github.com/status-im/nim.git --depth 1
  cd nim
  sh build_all.sh
  bin/nim c -d:release -o:bin/nimble dist/nimble/src/nimble
  cd ../..
}

sudo apt-get install -y cmake

export PATH=$PATH:$PWD/docker/nim/bin
export PKG_CONFIG_PATH=/opt/qt/5.12.0/gcc_64/lib/pkgconfig
export LD_LIBRARY_PATH=/opt/qt/5.12.0/gcc_64/lib/

cd ../..
nimble develop
cd examples/stratus

make clean appimage
