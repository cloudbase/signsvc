#!/bin/bash
set -e

source .env

out_file="$1"
out_file_signed="${out_file}_signed"

osslsigncode sign -h sha256 -pkcs11module /usr/lib/x86_64-linux-gnu/libykcs11.so \
-certs $CERT -key "pkcs11:pin-value=${PIN}" -ts $TS_URL \
-in $out_file -out $out_file_signed

cp $out_file_signed $out_file
rm $out_file_signed
