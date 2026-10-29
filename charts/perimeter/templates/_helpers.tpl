{{- define "perimeter.labels" -}}
app.kubernetes.io/name: perimeter
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "perimeter.selectorLabels" -}}
app.kubernetes.io/name: perimeter
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
