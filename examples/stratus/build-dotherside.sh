#!/bin/sh

rm -rf DOtherSide
git clone https://github.com/filcuc/DOtherSide.git --depth=1
cd DOtherSide
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=${1:-.} ..
make -j4 DOtherSideStatic
