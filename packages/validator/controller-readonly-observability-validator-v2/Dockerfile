FROM docker.io/library/python@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/validator-v2
COPY --chown=65532:65532 validator.py /opt/validator-v2/validator.py
COPY --chown=65532:65532 tests/run.py /opt/validator-v2/tests/run.py
COPY --chown=65532:65532 fixtures/ /fixtures/
COPY --chown=65532:65532 fixtures/known-bad/validation-fail/ /fixtures/known-bad/
USER 65532:65532
ENTRYPOINT ["python3", "-I", "/opt/validator-v2/validator.py"]
