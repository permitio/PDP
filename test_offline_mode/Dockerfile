FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.13.18-alpine3.23@sha256:d911085e59772e458649b0184ca311c309068961c5efa11d5761ea0c64a91383

RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    uv pip install --system permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
