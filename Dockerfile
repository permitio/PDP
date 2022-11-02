# BUILD STAGE ---------------------------------------
# split this stage to save time and reduce image size
# ---------------------------------------------------
FROM python:3.8 as BuildStage
# install linux libraries necessary to compile some python packages
RUN apt-get update && \
    apt-get install -y build-essential libffi-dev
# from now on, work in the /app directory
WORKDIR /app/
# Layer dependency install (for caching)
COPY requirements.txt requirements.txt
# install python deps
RUN pip install --upgrade pip && pip install --user -r requirements.txt

# MAIN IMAGE ----------------------------------------
# most of the time only this image should be built
# ---------------------------------------------------
FROM python:3.8-slim
RUN apt-get update && \
    apt-get install -y bash curl
# bash is needed for ./start/sh script
RUN curl -L -o /opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod 755 /opa
# copy libraries from build stage
COPY --from=BuildStage /root/.local /root/.local
# copy wait-for-it (use only for development! e.g: docker compose)
COPY scripts/wait-for-it.sh /usr/wait-for-it.sh
RUN chmod +x /usr/wait-for-it.sh
# copy startup script
COPY ./scripts/start.sh /start.sh
RUN chmod +x /start.sh
# copy gunicorn_config
COPY ./scripts/gunicorn_conf.py /gunicorn_conf.py
# copy app code
COPY . ./
# copy Kong route-to-resource translation table
RUN mkdir -p /config
COPY kong_routes.json /config/kong_routes.json
# install sidecar package
RUN python setup.py install
# Make sure scripts in .local are usable:
ENV PATH=/:/root/.local/bin:$PATH
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
# expose sidecar port
EXPOSE 7000
# expose opa directly
EXPOSE 8181
# run gunicorn
CMD ["/start.sh"]
