# add helm repository
helm repo add pdp https://permitio.github.io/sidecar

# search chart
helm search repo pdp


# Helm install
helm install pdp pdp/pdp --set pdp.ApiKey='<YOUR_API_KEY>' --create-namespace --namespace pdp --wait