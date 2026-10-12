FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM python:3.14-alpine3.23@sha256:e7cff362a12454395f8dc99607c21a602ea880cdce03538877b90c2ba932b16f

RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv pip install --system permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
