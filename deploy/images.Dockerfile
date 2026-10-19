# The container images the development and test tooling runs. Nothing is built from this file:
# it is the one place the images are named, pinned by digest with their tag kept for readers,
# in a format Dependabot's docker ecosystem understands (it updates tag and digest together).
#
# - scripts/test-java.js and scripts/e2e.js run the `maven` image (read through
#   scripts/images.js);
# - deploy/docker-compose.dev.yml and .github/workflows/ci.yml name the `postgres` image
#   themselves (compose and the CI service container cannot read this file); `npm run
#   images:check` fails when they differ from it. After a Dependabot update of this file, copy
#   the new postgres reference into both.

FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS maven
FROM postgres:16-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb AS postgres
