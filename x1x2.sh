#!/bin/bash

cd keys
CERTS=$(ls *.pem)
for f in $CERTS ; do cp $f x1_$f; done
for f in $CERTS ; do cp $f x2_$f; done
cd -