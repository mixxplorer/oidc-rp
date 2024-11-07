#!/bin/sh

set -xe

IDP_READY=https://idp:9000/health/ready

USERNAME=mytestuser
PASSWORD=mytestpassword
IDP_URL=https://idp:8443/realms/master
CLIENT_ID=oidc-rp

# At 120s logging interval and print at startup,
# we should see 2 access tokens by 120s.
# We give 2s extra leeway.
TEST_RUNTIME=122
TOKEN_COUNT_EXPECTED=2

EXEC=${1:-"/oidc-rp/account"}

echo "wait until IDP is ready"
curl -s -o /dev/null --insecure \
    --retry 30 --retry-delay 1 --retry-max-time 30 --retry-connrefused  \
    "$IDP_READY" \
|| ( echo "ERROR: IDP not ready in time: $?"; exit 1)

echo "Download IDP cert"
curl -s -w %{certs}  -o /dev/null --insecure "$IDP_READY" | \
    openssl x509 -inform pem -outform pem >> /etc/ssl/certs/ca-certificates.crt

echo "Start refreshing access tokens"
timeout --kill-after=10s --preserve-status "${TEST_RUNTIME}s" \
    "$EXEC" \
    -vvvv \
    --idp-url "$IDP_URL" --client-id "$CLIENT_ID" \
    --username "$USERNAME" --password "$PASSWORD" 2>&1\
    | tee /tmp/account_test_log.txt

TOKEN_COUNT=$(grep -F -c "[account] Access token" /tmp/account_test_log.txt)

if [ "$TOKEN_COUNT" -ne "$TOKEN_COUNT_EXPECTED" ]; then
    echo "ERROR: Found $TOKEN_COUNT refreshes, expected $TOKEN_COUNT_EXPECTED."
    exit 1
else
    echo "Found $TOKEN_COUNT as expected. test successful."
    exit 0
fi
