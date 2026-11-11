FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM python:3.13.18-alpine3.23@sha256:d911085e59772e458649b0184ca311c309068961c5efa11d5761ea0c64a91383

RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv pip install --system permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
