![PDP.png](imgs/PDP.png)
# Permit.io PDP
The PDP (Policy decision point) syncs with the authorization service and maintains up-to-date policy cache for open policy agent.

## Running locally (during development)
```
uvicorn horizon.main:app --reload --port=7000
```

you can pass environment variables to control the behavior of the sidecar:
e.g, running a local sidecar against production backend:
```
AUTHZ_SERVICE_URL=https://api.permit.io CLIENT_TOKEN=<CLIENT_TOKEN> uvicorn horizon.main:app --reload --port=7000
```

## Installing and running in production

Pull the image from docker hub
```
docker pull permitio/pdp-v2
```

Run the image: don't forget to pass your authorization service API KEY:
```
docker run -it -e "CLIENT_TOKEN=<YOUR API KEY>" -p 7000:7000 permitio/pdp-v2
```

By default the image exposes port 7000 but you can change it.

## Building the docker image yourself
on arm architecture:
```
VERSION=<TAG> make build-arm64
```
on amd64 architecture:
```
VERSION=<TAG> make build-amd64
```

## Running the image in development mode
```
VERSION=<TAG> API_KEY=<PDP_API_KEY> make run
```