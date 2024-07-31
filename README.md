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
docker pull permitio/pdp
```

Run the image: don't forget to pass your authorization service API KEY:
```
docker run -it -e "CLIENT_TOKEN=<YOUR API KEY>" -p 7000:7000 permitio/pdp
```

By default the image exposes port 7000 but you can change it.

## Building the docker image yourself
```
READ_ONLY_GITHUB_TOKEN=<GITHUB_TOKEN> make build
```
you must declare the environment variable `READ_ONLY_GITHUB_TOKEN` for this command to work.

## Running the image in development mode
```
DEV_MODE_CLIENT_TOKEN=<CLIENT_TOKEN> make run
```
you must declare the environment variable `DEV_MODE_CLIENT_TOKEN` for this command to work.





## TK Setup Instructions
Mac: 

Setup your envrironment:
```
brew update
brew install pyenv pyenv-virtualenv go

vi ~/.zshrc

#pyenv requirement
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

source ~/.zshrc

```
``` 
pyenv install 3.10
pyenv virtualenv 3.10 pdp
pyenv activate pdp 
```
Make sure your in the PDP root dir then run:

Note: fwiw I had to restart my mac for the python envs to be right. 
```
pip install -r requirements.txt
```
```
vi ~/.zshrc

#for PDP Dev
export UVICORN_NUM_WORKERS=1
export UVICORN_ASGI_APP=horizon.main:app
export UVICORN_PORT=7000
export OPAL_SERVER_URL=https://opal.permit.io
export OPAL_LOG_DIAGNOSE=false
export OPAL_LOG_TRACEBACK=false
export OPAL_LOG_MODULE_EXCLUDE_LIST="[]"
export OPAL_INLINE_OPA_ENABLED=true
export OPAL_INLINE_OPA_LOG_FORMAT=http
export PDP_CONTROL_PLANE=https://api.permit.io
export PDP_API_KEY="permit_key_"
export PDP_REMOTE_CONFIG_ENDPOINT=/v2/pdps/me/config
export PDP_REMOTE_STATE_ENDPOINT=/v2/pdps/me/state

source ~/.zshrc

```
I then installed a local copy of permit-opa
```
cd ..
gh repo clone permitio/permit-opa
cd permit-opa
go build -o opa

vi ~/.zshrc
# only way I could get opa to be found by python subprocess was to add to PATH
export PATH=$PATH:/Users/thomas/Code/permit-opa

source ~/.zshrc
```



Finally, run the app:
```
uvicorn horizon.main:app --reload --port=7000
```

OR

Build a local docker image
```
export VERSION=vzw2
make build-arm64   
```