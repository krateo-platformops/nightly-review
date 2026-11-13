{{- define "nightly-review.fullname" -}}
{{- printf "%s" (default "nightly-review" .Chart.Name) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
serviceAccountConfig for the reviewer Agent: spec.declarative.deployment.serviceAccountConfig.annotations
from .Values.reviewer.serviceAccount.annotations, and NOTHING when that map is empty, null or absent.
kagent creates and owns the Agent's ServiceAccount (named after the Agent), so the Agent spec is the
only place to annotate it (GKE Workload Identity: iam.gke.io/gcp-service-account). The field exists only
in kagent.dev/v1alpha2; under v1alpha1 the apiserver prunes it silently.

The same contract as krateo-agent-lib.serviceAccountConfig (krateo-agent-lib 0.2.0), kept here
because that library is private and this chart is public. The trims are load-bearing: the trailing
dash on `with` keeps the action's newline out of the caller's nindent, and the leading dash on toYaml
keeps a blank line from appearing under `annotations:`. hack/test-sa-annotations.py pins the contract.
*/}}
{{- define "nightly-review.serviceAccountConfig" -}}
{{- with ((.Values.reviewer | default dict).serviceAccount | default dict).annotations -}}
serviceAccountConfig:
  annotations:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}
