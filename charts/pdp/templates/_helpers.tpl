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
