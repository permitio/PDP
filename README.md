# add helm repository
helm repo add pdp https://permitio.github.io/sidecar

# search chart
helm search repo pdp

# install chart
helm install pdp pdp/pdp --set pdp.ApiKey=<API_KEY> --create-namespace --namespace pdp --wait  