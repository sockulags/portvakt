{{/* Names and labels. */}}
{{- define "portvakt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "portvakt.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "portvakt.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "portvakt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: portvakt
{{- end -}}

{{/* Selector labels of one component: include with (dict "root" . "component" "server"). */}}
{{- define "portvakt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "portvakt.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Labels of a component's pods: its selector labels plus the release's version. */}}
{{- define "portvakt.podLabels" -}}
{{ include "portvakt.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/part-of: portvakt
{{- end -}}

{{- define "portvakt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "portvakt.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference: (dict "root" . "image" .Values.server.image). */}}
{{- define "portvakt.image" -}}
{{- $repository := printf "%s%s" .root.Values.imageRegistry .image.repository -}}
{{- if .image.digest -}}
{{- printf "%s@%s" $repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Origins: explicit values, otherwise https://{ingress host}. */}}
{{- define "portvakt.publicUrl" -}}
{{- default (printf "https://%s" .Values.ingress.host) .Values.server.publicUrl | trimSuffix "/" -}}
{{- end -}}

{{- define "portvakt.adminPublicUrl" -}}
{{- default (printf "https://%s" .Values.ingress.adminHost) .Values.server.adminPublicUrl | trimSuffix "/" -}}
{{- end -}}

{{- define "portvakt.serverSecret" -}}
{{- default (printf "%s-server" (include "portvakt.fullname" .)) .Values.server.existingSecret -}}
{{- end -}}

{{- define "portvakt.ownerSecret" -}}
{{- default (printf "%s-db-owner" (include "portvakt.fullname" .)) .Values.database.ownerSecret -}}
{{- end -}}

{{- define "portvakt.adminSecret" -}}
{{- default (printf "%s-admin" (include "portvakt.fullname" .)) .Values.admin.existingSecret -}}
{{- end -}}

{{/* The server's highest replica count (the HPA maximum when autoscaling). */}}
{{- define "portvakt.maxServerReplicas" -}}
{{- if .Values.server.autoscaling.enabled -}}
{{- .Values.server.autoscaling.maxReplicas -}}
{{- else -}}
{{- .Values.server.replicas -}}
{{- end -}}
{{- end -}}

{{/*
Database connections the release may hold at once (docs/operations.md, "Capacity"): each server
replica DATABASE_POOL_MAX + 1 LISTEN connection, the migration and audit prune jobs one each, the
admin BFF's pool (10 per replica) when its sessions live on the same database server. During a
rolling update one extra pod of each Deployment runs (maxSurge 1).
*/}}
{{- define "portvakt.databaseConnections" -}}
{{- $server := mul (add (int (include "portvakt.maxServerReplicas" .)) 1) (add (int .Values.server.databasePoolMax) 1) -}}
{{- $admin := 0 -}}
{{- if and .Values.admin.enabled .Values.database.adminSharesServer -}}
{{- $admin = mul (add (int .Values.admin.replicas) 1) 10 -}}
{{- end -}}
{{- add $server $admin 2 -}}
{{- end -}}

{{/*
Pod-level settings shared by every Portvakt pod: (dict "root" . "hook" false). Hook Jobs run
before the chart's ServiceAccount exists on the first install, so they use the namespace's
default one, without a token either way.
*/}}
{{- define "portvakt.podSecurity" -}}
{{- if not .hook }}
serviceAccountName: {{ include "portvakt.serviceAccountName" .root }}
automountServiceAccountToken: {{ .root.Values.serviceAccount.automountServiceAccountToken }}
{{- else }}
automountServiceAccountToken: false
{{- end }}
securityContext:
  {{- toYaml .root.Values.podSecurityContext | nindent 2 }}
{{- with .root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Topology spread over zones and nodes: (dict "root" . "component" "server" "spread" ...). */}}
{{- define "portvakt.topologySpread" -}}
{{- if .spread.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: {{ .spread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "portvakt.selectorLabels" (dict "root" .root "component" .component) | nindent 8 }}
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: {{ .spread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "portvakt.selectorLabels" (dict "root" .root "component" .component) | nindent 8 }}
{{- end }}
{{- end -}}

{{/*
Environment of the server's one-off jobs (migrations, audit prune): the owner URL from the owner
Secret, and the runtime URL (its role is the one the migration runner grants).
*/}}
{{- define "portvakt.jobDatabaseEnv" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "portvakt.serverSecret" . }}
      key: DATABASE_URL
- name: MIGRATION_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "portvakt.ownerSecret" . }}
      key: MIGRATION_DATABASE_URL
{{- end -}}

{{/* NetworkPolicy rules (templates/networkpolicy.yaml): DNS, and the database. */}}
{{- define "portvakt.np.dns" -}}
- to:
    - namespaceSelector:
        {{- toYaml .dns.namespaceSelector | nindent 8 }}
      podSelector:
        {{- toYaml .dns.podSelector | nindent 8 }}
  ports:
    - { protocol: UDP, port: 53 }
    - { protocol: TCP, port: 53 }
{{- end -}}
{{- define "portvakt.np.database" -}}
- to:
    {{- range .database.cidrs }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
    {{- if or .database.podSelector .database.namespaceSelector }}
    - {{- with .database.namespaceSelector }}
      namespaceSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .database.podSelector }}
      podSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    {{- end }}
  ports:
    - { protocol: TCP, port: {{ .database.port }} }
{{- end -}}
