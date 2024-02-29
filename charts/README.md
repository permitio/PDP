# Permit.io PDP
The PDP (Policy decision point) syncs with the authorization service and maintains up-to-date policy cache for open policy agent.

# Permit.io PDP - helm install

helm install pdp . --set pdp.ApiKey=${{ secrets.PDP_API_KEY }} --create-namespace --namespace pdp --wait