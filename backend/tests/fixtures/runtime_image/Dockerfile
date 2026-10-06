# Contract fixture for the bugforge-runtime-v1 input/output protocol. It is NOT an
# EVM. It echoes the requested identity so the Docker plumbing (read-only manifest,
# exit status, artifact collection) can be tested. Build it locally; tests never
# pull or build images:
#   docker build -t bugforge/runtime-contract-fixture:local tests/fixtures/runtime_image
# then set SECURITY_AGENT_RUNTIME_IMAGE=bugforge/runtime-contract-fixture:local
FROM python:3.12-slim
COPY bugforge-runtime /usr/local/bin/bugforge-runtime
RUN chmod 0755 /usr/local/bin/bugforge-runtime
