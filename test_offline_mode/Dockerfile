FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM python:3.13-alpine3.23@sha256:6438599575cca0d1df94aeee0d2ae088d4d8846eab554b2ee7784a3a6df0d516

RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv pip install --system permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
