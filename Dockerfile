# BUILD STAGE ---------------------------------------
# split this stage to save time and reduce image size
# ---------------------------------------------------
FROM python:3.10 as BuildStage
# install linux libraries necessary to compile some python packages
RUN apt-get update && \
    apt-get install -y build-essential libffi-dev
# from now on, work in the /app directory
WORKDIR /app/

# install python deps
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip && pip install setuptools -U && pip install --user -r requirements.txt

# Install a custom OPAL, if requested
COPY custom /custom

RUN if [ -f /custom/custom_opal.tar.gz ]; \
	then \
		cd /custom && \
		tar xzf custom_opal.tar.gz && \
		pip install --user packages/opal-common packages/opal-client && \
		cd / && \
		rm -rf /custom ; \
	fi

COPY horizon setup.py MANIFEST.in ./
RUN python setup.py install --user

FROM golang:bullseye as OPABuildStage

COPY custom /custom

RUN if [ -f /custom/custom_opa.tar.gz ]; \
    then \
      cd /custom && \
      tar xzf custom_opa.tar.gz && \
      go build -o /opa && \
      rm -rf /custom ; \
    else \
      case $(uname -m) in \
      	x86_64) \
      		curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static ; \
      		;; \
      	aarch64) \
      		curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_arm64_static ; \
      		;; \
      	*) \
      		echo "Unknown architecture." ; \
      		exit 1 ; \
      		;; \
      esac ; \
    fi

# Layer dependency install (for caching)

# MAIN IMAGE ----------------------------------------
# most of the time only this image should be built
# ---------------------------------------------------
FROM python:3.13.0a3-slim
RUN apt-get update && \
    apt-get install -y bash curl

RUN groupadd -r permit
RUN useradd -m -s /bin/bash -g permit -d /home/permit permit

# copy libraries from build stage
RUN mkdir /home/permit/.local
COPY --from=BuildStage /root/.local /home/permit/.local

COPY --from=OPABuildStage --chmod=755 /opa /opa

# bash is needed for ./start/sh script
COPY scripts ./

RUN mkdir -p /config
RUN chown -R permit:permit /opa
RUN chown -R permit:permit /config

# copy wait-for-it (use only for development! e.g: docker compose)
COPY scripts/wait-for-it.sh /usr/wait-for-it.sh
RUN chmod +x /usr/wait-for-it.sh
# copy startup script
COPY ./scripts/start.sh /start.sh
RUN chmod +x /start.sh



RUN chown -R permit:permit /home/permit
RUN chown -R permit:permit /usr/
USER permit

# copy Kong route-to-resource translation table
COPY kong_routes.json /config/kong_routes.json
# install sidecar package

# copy gunicorn_config
COPY ./scripts/gunicorn_conf.py /gunicorn_conf.py
# copy app code
COPY . ./
# Make sure scripts in .local are usable:
ENV PATH=/:/home/permit/.local/bin:$PATH
# uvicorn config ------------------------------------

# WARNING: do not change the number of workers on the opal client!
# only one worker is currently supported for the client.

# number of uvicorn workers
ENV UVICORN_NUM_WORKERS=1
# uvicorn asgi app
ENV UVICORN_ASGI_APP=horizon.main:app
# uvicorn port
ENV UVICORN_PORT=7000

# opal configuration --------------------------------
ENV OPAL_SERVER_URL=https://opal.permit.io
ENV OPAL_LOG_DIAGNOSE=false
ENV OPAL_LOG_TRACEBACK=false
ENV OPAL_LOG_MODULE_EXCLUDE_LIST="[]"
ENV OPAL_INLINE_OPA_ENABLED=true
ENV OPAL_INLINE_OPA_LOG_FORMAT=http

# horizon configuration -----------------------------
# by default, the backend is at port 8000 on the docker host
# in prod, you must pass the correct url
ENV PDP_CONTROL_PLANE=https://api.permit.io
ENV PDP_API_KEY="MUST BE DEFINED"
ENV PDP_REMOTE_CONFIG_ENDPOINT=/v2/pdps/me/config
ENV PDP_REMOTE_STATE_ENDPOINT=/v2/pdps/me/state
# expose sidecar port
EXPOSE 7000
# expose opa directly
EXPOSE 8181
# run gunicorn
CMD ["/start.sh"]
