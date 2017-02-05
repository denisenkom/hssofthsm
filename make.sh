#!/bin/bash
set -xe
~/.cabal/bin/c2hs --cppopts=-Iinclude/ System/Crypto/Pkcs11Imports.chs
ghc -dynamic -fPIC -c System/Crypto/Pkcs11Imports.hs System/Crypto/SoftHsm.hs -I=include/:System/Crypto
ghc -dynamic -optc-std=c++11 -fPIC -c export.cpp -I=include/:System/Crypto
ghc -dynamic -shared System/Crypto/SoftHsm.o System/Crypto/Pkcs11Imports.o export.o  -lHSrts-ghc8.0.1 -package bytestring -package cryptohash -o libhsm.so
pkcs11-tool -t --module ./libhsm.so
