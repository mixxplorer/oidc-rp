#!/bin/sh

set -xe

IDP_READY=https://idp:9000/health/ready

USERNAME=mytestuser
PASSWORD=mytestpassword
IDP_URL=https://idp:8443/realms/master
CLIENT_ID=oidc-rp

EXEC=${1:-"/oidc-rp/auth_verify"}

echo "wait until IDP is ready"
curl -s -o /dev/null --insecure \
    --retry 30 --retry-delay 1 --retry-max-time 30 --retry-connrefused  \
    "$IDP_READY" \
|| ( echo "ERROR: IDP not ready in time: $?"; exit 1)

echo "Download IDP cert"
curl -s -w %{certs}  -o /dev/null --insecure "$IDP_READY" | \
    openssl x509 -inform pem -outform pem >> /etc/ssl/certs/ca-certificates.crt

echo "Run verification example"
"$EXEC" \
    -vvvv \
    --idp-url "$IDP_URL" --client-id "$CLIENT_ID" \
    --username "$USERNAME" --password "$PASSWORD"
