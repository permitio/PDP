FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

FROM python:3.13-alpine3.23@sha256:6438599575cca0d1df94aeee0d2ae088d4d8846eab554b2ee7784a3a6df0d516

RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv pip install --system permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
