#!/bin/sh

# Generate the protobuf files
buf generate

# move the generated files to the correct location
cp -r github.com/nghuyenthevinh2000/bitcoin-playground/* ./
rm -rf github.com