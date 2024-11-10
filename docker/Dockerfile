# Based on: https://github.com/jessfraz/dockerfiles/tree/master/ykman
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
	pcscd procps \
	yubikey-manager osslsigncode ykcs11 libengine-pkcs11-openssl

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

WORKDIR /root/
COPY docker/entrypoint.sh /usr/local/bin/

EXPOSE 443

COPY signsvc .
COPY sign.sh .
COPY certificate.cer .
COPY .env .
COPY cert/cert.pem cert/
COPY cert/key.pem cert/

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
