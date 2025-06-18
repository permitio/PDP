{{/*
Selector labels
*/}}
{{- define "pdp.selectorLabels" -}}
app: permitio-pdp
{{- end }}

{{/*
Common labels
*/}}
{{- define "pdp.labels" -}}
{{ include "pdp.selectorLabels" . }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Get the secret name for the API key
*/}}
{{- define "pdp.secretName" -}}
{{- if .Values.pdp.existingApiKeySecret -}}
{{- .Values.pdp.existingApiKeySecret.name -}}
{{- else -}}
permitio-pdp-secret
{{- end -}}
{{- end }}

{{/*
Get the secret key for the API key
*/}}
{{- define "pdp.secretKey" -}}
{{- if .Values.pdp.existingApiKeySecret -}}
{{- .Values.pdp.existingApiKeySecret.key -}}
{{- else -}}
ApiKey
{{- end -}}
{{- end }}
