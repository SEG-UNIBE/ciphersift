# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The CipherSift Authors
FROM maven:3.9-eclipse-temurin-25 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN mvn -B -ntp verify

FROM eclipse-temurin:25-jre
RUN useradd --create-home --uid 10001 ciphersift
COPY --from=build /src/target/ciphersift-*-all.jar /opt/ciphersift/ciphersift.jar
USER ciphersift
ENV XDG_CACHE_HOME=/tmp/ciphersift-cache \
    LC_ALL=C.UTF-8
WORKDIR /scan
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/opt/ciphersift/ciphersift.jar"]
CMD ["--help"]
