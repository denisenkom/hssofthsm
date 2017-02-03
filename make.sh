#!/bin/bash
ghc -dynamic -fPIC -c System/Crypto/SoftHsm.hs export.c -I=include/
ghc -dynamic -shared System/Crypto/SoftHsm.o export.o  -lHSrts-ghc8.0.1 -o libhsm.so
pkcs11-tool -t --module ./libhsm.so
