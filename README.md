# add helm repository
```sh
helm repo add pdp https://permitio.github.io/PDP
```
# search chart
```sh
helm search repo pdp
```
# Helm install
```sh
helm install pdp pdp/pdp --set pdp.ApiKey=<API_KEY> --create-namespace --namespace pdp --wait
```
