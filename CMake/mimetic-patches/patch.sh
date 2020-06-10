#!/bin/bash
for file in "$1/mimetic-patches"/*.patch;
do
  patch -p0 < $file || true;
done
