# The container images Portvakt is built on and the development and test tooling runs. Nothing
# is built from this file: it is the one place the images are named, pinned by digest with their
# tag kept for readers, in a format Dependabot's docker ecosystem understands (it updates tag and
# digest together).
#
# - deploy/Dockerfile builds every Portvakt image on the `node` image (each FROM names it);
# - scripts/test-java.js and scripts/e2e.js run the `maven` image, scripts/helm-check.js the
#   `helm` and `kubeconform` images (read through scripts/images.js);
# - deploy/docker-compose.dev.yml, deploy/docker-compose.yml and .github/workflows/ci.yml name
#   the `postgres` image themselves (compose and the CI service container cannot read this file).
#
# `npm run images:check` fails when deploy/Dockerfile or those files differ from this list. After
# a Dependabot update of one of them, copy the new reference into the others.

FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS node
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS maven
FROM postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873 AS postgres
FROM alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e AS helm
FROM ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e AS kubeconform
