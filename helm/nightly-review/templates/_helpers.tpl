{{- define "nightly-review.fullname" -}}
{{- printf "%s" (default "nightly-review" .Chart.Name) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
