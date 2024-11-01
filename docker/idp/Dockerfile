# Dedicated image for preconfigured Keycloak, required to use it as a service in .gitlab-ci.yml.
# https://github.com/keycloak/keycloak/issues/10216#issuecomment-1090899777

FROM quay.io/keycloak/keycloak:latest AS builder

WORKDIR /opt/keycloak

RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=idp" -alias server -keystore conf/server.keystore
RUN /opt/keycloak/bin/kc.sh build

COPY realm-export.json /opt/keycloak_import/
RUN /opt/keycloak/bin/kc.sh import --file /opt/keycloak_import/realm-export.json

FROM quay.io/keycloak/keycloak:latest

ENV KC_HEALTH_ENABLED=true
COPY --from=builder /opt/keycloak/ /opt/keycloak/
EXPOSE 8080 8443 9000

CMD [ "start-dev" ]
