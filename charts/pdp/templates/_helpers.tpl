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
Fail on API key settings that contradict each other or that a template would misread
*/}}
{{- define "pdp.validateApiKeySource" -}}
{{- $userProvidedSecret := .Values.pdp.userProvidedSecret | default false -}}
{{- if not (kindIs "bool" $userProvidedSecret) -}}
{{- fail (printf "pdp.userProvidedSecret must be true or false, got the %s %q. A quoted \"false\" counts as set and would drop PDP_API_KEY." (kindOf $userProvidedSecret) (toString $userProvidedSecret)) -}}
{{- end -}}
{{- if and $userProvidedSecret .Values.pdp.existingApiKeySecret -}}
{{- fail "pdp.userProvidedSecret and pdp.existingApiKeySecret cannot both be set: existingApiKeySecret makes the chart read PDP_API_KEY from that Secret, userProvidedSecret makes it read no Secret at all. Unset one of them." -}}
{{- end -}}
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
