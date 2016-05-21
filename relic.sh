#!/usr/bin/env bash

pushd relic
rm -rf CMakeCache.txt CMakeFiles
cmake -DALIGN=16 -DARCH=X64 -DARITH=curve2251-sse -DCHECK=off -DFB_POLYN=251 \
      -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -march=native -msse4.2 -mpclmul" \
      -DTIMER=CYCLE -DWORD=64 -DRAND="HASH" .
make clean
make
popd
