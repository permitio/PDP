{{/*
Expand the name of the chart.
*/}}
{{- define "pdp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "pdp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

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
{{- if .Values.useStandardHelmNamingConventions }}
{{- include "pdp.fullname" . }}
{{- else -}}
permitio-pdp-secret
{{- end -}}
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
