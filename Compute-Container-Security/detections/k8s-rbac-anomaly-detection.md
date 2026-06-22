# detections/k8s-rbac-anomaly-detection.md

> **Level:** Intermediate–Advanced
> **Prereqs:** 03-05 (K8s Attack Surface), 03-06 (RBAC & SA Tokens)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Privilege Escalation, Credential Access, Persistence (see ATT&CK Containers matrix)
**Authorization scope:** All detection rules target your own clusters. Log queries use placeholder account IDs, resource IDs, and IPs (`198.51.100.1` from TEST-NET-2 per RFC 5737).

## Purpose

Provide copy-pasteable detection rules (Falco, SIEM queries, cloud-native alerts) for anomalous Kubernetes RBAC behavior: unexpected kubectl exec into `kube-system`, token enumeration across namespaces, cluster-admin binding creation, and credential access from unexpected source IPs.

## Detection scenario 1 — kubectl exec into kube-system from non-admin namespace

**Tactic:** Privilege Escalation, Execution
**Description:** An attacker with a pod shell in `default` namespace creates a `kubectl exec` into `kube-system` to access control-plane components or steal their service account tokens.

### Falco rule

```yaml
- rule: Kubectl Exec into Kube-System
  desc: Detect kubectl exec targeting kube-system namespace from an unexpected user
  condition: >
    ka.target.resource=pods/exec and
    ka.target.namespace=kube-system and
    not ka.user.name startswith "system:node" and
    not ka.user.name startswith "system:serviceaccount:kube-system" and
    not ka.user.name startswith "system:kube" and
    not ka.user.name startswith "kubernetes-admin"
  output: >
    kubectl exec into kube-system detected!
    User: %ka.user.name
    From: %ka.source.ips
    Pod: %ka.target.namespace/%ka.target.name
    Command: %ka.uri
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, execution, privilege-escalation]
```

### K8s audit log query (jq)

```bash
cat audit.log | jq 'select(
  .objectRef.resource == "pods" and
  .objectRef.subresource == "exec" and
  .objectRef.namespace == "kube-system" and
  (.user.username | startswith("system:serviceaccount:default:"))
) | {time: .stageTimestamp, user: .user.username, pod: .objectRef.name, ip: .sourceIPs}'
```

### Cloud-native SIEM queries

**AWS CloudWatch Logs Insights (EKS):**

```
fields @timestamp, user.username, objectRef.name, sourceIPs.0, requestURI
| filter objectRef.resource = "pods" and objectRef.subresource = "exec"
| filter objectRef.namespace = "kube-system"
| filter user.username like /serviceaccount:default:/
| sort @timestamp desc
| limit 50
```

**Azure Monitor Logs (AKS — kube-audit admin log):**

```
AzureDiagnostics
| where Category == "kube-audit-admin"
| where log_s contains "pods/exec" and log_s contains "kube-system"
| where log_s contains "system:serviceaccount:default:"
| project TimeGenerated, User=parse_json(log_s).user.username, Pod=parse_json(log_s).objectRef.name, SourceIP=parse_json(log_s).sourceIPs
```

**GCP Cloud Logging (GKE):**

```
resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
protoPayload.resourceName=~"namespaces/kube-system/pods/.*"
protoPayload.authenticationInfo.principalEmail=~"system:serviceaccount:default:.*"
```

## Detection scenario 2 — cluster-admin RoleBinding creation

**Tactic:** Persistence, Privilege Escalation
**Description:** A new ClusterRoleBinding referencing `cluster-admin` is created for a non-system ServiceAccount. This is the most common K8s privilege escalation path.

### Falco rule

```yaml
- rule: ClusterAdmin Binding to ServiceAccount
  desc: Detect ClusterRoleBinding granting cluster-admin to a ServiceAccount outside kube-system
  condition: >
    ka.target.resource=clusterrolebindings and
    ka.verb=create and
    ka.target.rbac.role_ref_name=cluster-admin and
    ka.target.rbac.subjects.kind=ServiceAccount and
    not ka.target.rbac.subjects.namespace startswith "kube-system"
  output: >
    cluster-admin bound to ServiceAccount!
    User: %ka.user.name
    SA: %ka.target.rbac.subjects.namespace/%ka.target.rbac.subjects.name
    Binding: %ka.target.name
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, persistence, privilege-escalation]
```

### K8s audit log query (jq)

```bash
cat audit.log | jq 'select(
  .verb == "create" and
  .objectRef.resource == "clusterrolebindings" and
  .responseObject.roleRef.name == "cluster-admin" and
  (.responseObject.subjects[]?.kind == "ServiceAccount") and
  (.responseObject.subjects[]?.namespace | startswith("kube-system") | not)
) | {time: .stageTimestamp, creator: .user.username, binding: .objectRef.name, sa: (.responseObject.subjects[])}'
```

### Cloud-native SIEM queries

**AWS CloudWatch Logs Insights (EKS):**

```
fields @timestamp, user.username, objectRef.name
| filter objectRef.resource = "clusterrolebindings" and verb = "create"
| sort @timestamp desc
| limit 50
```

**Azure Monitor Logs (AKS):**

```
AzureDiagnostics
| where Category == "kube-audit-admin"
| where log_s contains "clusterrolebindings" and log_s contains "create"
| project TimeGenerated, User=parse_json(log_s).user.username, Binding=parse_json(log_s).objectRef.name
```

**GCP Cloud Logging (GKE):**

```
resource.type="k8s_cluster"
protoPayload.methodName=~"io.k8s.rbac.authorization.k8s.io.v1.clusterrolebindings.(create|patch)"
```

## Detection scenario 3 — RBAC enumeration (Discovery)

**Tactic:** Discovery
**Description:** An attacker enumerates Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings to find escalation paths.

### Falco rule

```yaml
- rule: RBAC Enumeration
  desc: Detect bulk listing of RBAC resources from unexpected source
  condition: >
    ka.verb in (list, get) and
    ka.target.resource in (roles, clusterroles, rolebindings, clusterrolebindings) and
    not ka.user.name startswith "system:kube" and
    not ka.user.name startswith "system:serviceaccount:kube-system" and
    not ka.user.name startswith "kubernetes-admin"
  output: >
    RBAC enumeration detected!
    User: %ka.user.name
    Resource: %ka.target.resource
    Namespace: %ka.target.namespace
    SourceIP: %ka.source.ips
  priority: WARNING
  source: k8s_audit
  tags: [k8s, rbac, discovery]
```

### K8s audit log query (jq)

```bash
cat audit.log | jq 'select(
  .verb == "list" and
  (.objectRef.resource == "roles" or
   .objectRef.resource == "clusterroles" or
   .objectRef.resource == "rolebindings" or
   .objectRef.resource == "clusterrolebindings") and
  (.user.username | startswith("system:serviceaccount:default:"))
) | {time: .stageTimestamp, user: .user.username, resource: .objectRef.resource, ip: .sourceIPs[0]}'
```

## Detection scenario 4 — ServiceAccount token enumeration and exfiltration

**Tactic:** Credential Access
**Description:** An attacker who gains pod access lists Secrets (especially SA token secrets) in namespaces they should not access. Token exfiltration to a new external IP is a strong signal.

### Falco rule

```yaml
- rule: Secret Enumeration Across Namespaces
  desc: Detect a ServiceAccount listing secrets in a namespace different from its own
  condition: >
    ka.target.resource=secrets and
    ka.verb in (list, get) and
    ka.user.name startswith "system:serviceaccount:" and
    ka.target.namespace != ka.user.extra.serviceaccount.namespace
  output: >
    Cross-namespace secret access!
    SA: %ka.user.name (from ns=%ka.user.extra.serviceaccount.namespace)
    Target NS: %ka.target.namespace
    SourceIP: %ka.source.ips
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, credential-access]
```

### K8s audit log query (jq)

```bash
cat audit.log | jq 'select(
  (.user.username | startswith("system:serviceaccount:")) and
  .objectRef.resource == "secrets" and
  .objectRef.namespace != null and
  (.objectRef.namespace as $target |
   .user.username | split(":")[2] as $sa_ns |
   $target != $sa_ns)
) | {time: .stageTimestamp, user: .user.username, secret: .objectRef.name, target_ns: .objectRef.namespace, ip: .sourceIPs[0]}'
```

### Cloud-native SIEM queries

**AWS CloudWatch Logs Insights (EKS):**

```
fields @timestamp, user.username, objectRef.name, objectRef.namespace, sourceIPs.0
| filter objectRef.resource = "secrets" and verb in ["get", "list"]
| filter user.username like /serviceaccount:default:/
| filter objectRef.namespace != "default"
| sort @timestamp desc
| limit 50
```

**Azure Monitor Logs (AKS):**

```
AzureDiagnostics
| where Category == "kube-audit-admin"
| where log_s contains "secrets" and (log_s contains "list" or log_s contains "get")
| where log_s contains "system:serviceaccount:"
| project TimeGenerated, User=parse_json(log_s).user.username, Secret=parse_json(log_s).objectRef.name, Namespace=parse_json(log_s).objectRef.namespace, IP=parse_json(log_s).sourceIPs[0]
```

**GCP Cloud Logging (GKE):**

```
resource.type="k8s_cluster"
protoPayload.methodName=~"io.k8s.core.v1.secrets.(list|get)"
-protoPayload.authenticationInfo.principalEmail=~"system:serviceaccount:kube-system:.*"
-protoPayload.authenticationInfo.principalEmail=~"system:kube-.*"
```

## Detection scenario 5 — New source IP for kubeconfig authentication

**Tactic:** Initial Access, Persistence
**Description:** A kubeconfig credential (certificate or bearer token) is used from a source IP that has never authenticated to the API server before. Indicates stolen kubeconfig or token reuse from a new location.

### Falco rule

```yaml
- rule: New Source IP for Existing User
  desc: Alert when a known user authenticates from a previously unseen source IP
  condition: >
    ka.source.ips exists and
    not ka.source.ips in (whitelisted_ips) and
    not ka.user.name startswith "system:"
  output: >
    New source IP for user %ka.user.name!
    IP: %ka.source.ips
    User-Agent: %ka.useragent
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, initial-access]
```

### K8s audit log query — new IP detection with a lookup

```bash
# Baseline: collect known IPs per user over the last 30 days
cat audit.log | jq -r 'select(.user.username != null) | [.user.username, .sourceIPs[]?] | @tsv' | \
  sort -u > /tmp/user_ip_baseline.txt

# Alert: check today's audit log for IPs not in the baseline
cat /var/log/kubernetes/audit.log | jq -r 'select(.user.username != null) | [.user.username, .sourceIPs[]?] | @tsv' | \
  sort -u | while read user ip; do
    if ! grep -qF "${user}	${ip}" /tmp/user_ip_baseline.txt; then
      echo "NEW IP: $user from $ip"
    fi
  done
```

### Cloud-native SIEM queries

**AWS CloudWatch Logs Insights — new source IP per user (EKS):**

```
fields @timestamp, user.username, sourceIPs.0
| filter user.username not like /system:/
| stats earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen by user.username, sourceIPs.0
| sort first_seen desc
| limit 50
```

**GCP Cloud Logging — new source IP (GKE):**

```
resource.type="k8s_cluster"
protoPayload.authenticationInfo.principalEmail!~"system:.*"
protoPayload.requestMetadata.callerIp=("198.51.100.1" OR "198.51.100.2")
```

## Aggregated Falco rules file

```yaml
# k8s-rbac-anomalies.yaml — deploy via:
# kubectl create configmap falco-k8s-rules --from-file=k8s-rbac-anomalies.yaml -n falco
# Then mount as additionalRules in falco values.yaml

- rule: Kubectl Exec into Kube-System
  desc: Detect kubectl exec targeting kube-system from unexpected user
  condition: >
    ka.target.resource=pods/exec and
    ka.target.namespace=kube-system and
    not ka.user.name startswith "system:node" and
    not ka.user.name startswith "system:serviceaccount:kube-system" and
    not ka.user.name startswith "system:kube"
  output: "EXEC into kube-system: user=%ka.user.name target=%ka.target.name ns=%ka.target.namespace ips=%ka.source.ips"
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, privilege-escalation]

- rule: ClusterAdmin Binding to SA
  desc: ClusterRoleBinding granting cluster-admin to ServiceAccount outside kube-system
  condition: >
    ka.target.resource=clusterrolebindings and
    ka.verb=create and
    ka.target.rbac.role_ref_name=cluster-admin and
    ka.target.rbac.subjects.kind=ServiceAccount and
    not ka.target.rbac.subjects.namespace startswith "kube-system"
  output: "CLUSTER-ADMIN binding: user=%ka.user.name SA=%ka.target.rbac.subjects.namespace/%ka.target.rbac.subjects.name"
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, persistence]

- rule: RBAC Discovery Activity
  desc: Bulk listing of RBAC resources from non-control-plane user
  condition: >
    ka.verb in (list, get) and
    ka.target.resource in (roles, clusterroles, rolebindings, clusterrolebindings) and
    not ka.user.name startswith "system:"
  output: "RBAC enumeration: user=%ka.user.name resource=%ka.target.resource ips=%ka.source.ips"
  priority: WARNING
  source: k8s_audit
  tags: [k8s, rbac, discovery]

- rule: Cross-Namespace Secret Access
  desc: ServiceAccount listing secrets outside its own namespace
  condition: >
    ka.target.resource=secrets and
    ka.verb in (list, get) and
    ka.user.name startswith "system:serviceaccount:"
  output: "Secret access: SA=%ka.user.name target=%ka.target.namespace/%ka.target.name ips=%ka.source.ips"
  priority: CRITICAL
  source: k8s_audit
  tags: [k8s, rbac, credential-access]

- rule: Pod Created with hostPath Volume
  desc: Any pod creation with hostPath volumes (potential escape)
  condition: >
    ka.target.resource=pods and
    ka.verb=create and
    ka.target.pod.spec.volumes.hostpath exists
  output: "hostPath pod: user=%ka.user.name pod=%ka.target.namespace/%ka.target.name path=%ka.target.pod.spec.volumes.hostpath.path"
  priority: WARNING
  source: k8s_audit
  tags: [k8s, escape, defense-evasion]
```

## Cloud Custodian policy — detect over-privileged ClusterRoleBindings

```yaml
# Run: custodian run -s output policy.yaml
# Works for EKS (k8s resource) — adapt for AKS/GKE namespaces
policies:
  - name: audit-cluster-admin-bindings
    resource: k8s.cluster-role-binding
    description: Flag any non-system cluster-admin bindings
    filters:
      - type: value
        key: roleRef.name
        value: cluster-admin
        op: eq
      - not:
          - type: value
            key: "subjects[0].name"
            value: "system:.*"
            op: regex
    actions:
      - type: notify
        template: cluster-admin-binding
```

## CLI audit one-liners (cloud-specific)

```bash
# EKS: stream CloudWatch audit logs and grep for exec into kube-system
aws logs tail /aws/eks/cluster-sec/cluster --since 1h | \
  jq 'select(.objectRef.resource=="pods" and .objectRef.subresource=="exec" and .objectRef.namespace=="kube-system")'

# AKS: query kube-audit logs for RBAC enumeration
az monitor log-analytics query \
  --workspace $(az monitor log-analytics workspace show -g rg-sec -n ws-sec --query id -o tsv) \
  --analytics-query 'AzureDiagnostics | where Category == "kube-audit-admin" | where log_s contains "clusterroles" or log_s contains "clusterrolebindings" | limit 50'

# GKE: query Cloud Logging for secret access anomalies
gcloud logging read \
  'resource.type="k8s_cluster"
   protoPayload.methodName=~"io.k8s.core.v1.secrets.(list|get)"
   -protoPayload.authenticationInfo.principalEmail=~"system:.*"' \
  --project=my-sandbox-project --limit=50 --format="json(protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName, timestamp)"

# OnPrem: tail local audit log for RBAC anomalies
tail -f /var/log/kubernetes/audit.log | jq --unbuffered 'select(
  (.verb == "list" or .verb == "get") and
  (.objectRef.resource == "secrets" or .objectRef.resource == "clusterroles") and
  .user.username != null and
  (.user.username | startswith("system:kube") | not)
) | {time: .requestReceivedTimestamp, user: .user.username, resource: .objectRef.resource, ip: .sourceIPs[0]}'
```

## Recommended alert thresholds

| Detection | Baseline Behavior | Alert Threshold |
|---|---|---|
| kubectl exec into kube-system | 0 events (outside system SAs) | Any occurrence |
| cluster-admin binding to SA | 0 events (outside kube-system) | Any occurrence |
| RBAC enumeration | `kubectl auth can-i --list` from CI/CD (expected) | >5 different RBAC resource types listed within 60 seconds |
| Cross-namespace secret access | 0 events (outside system SAs) | Any occurrence |
| New source IP for existing user | IP rotation is normal for mobile/remote | Any IP outside known corporate CIDR and cloud shell ranges |
| hostPath pod creation | 0 events in user namespaces | Any occurrence outside kube-system |

## Deployment instructions

**Falco on managed K8s:**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falco.auditLog.enabled=true \
  --set-file falco.rulesFile.customRules=k8s-rbac-anomalies.yaml
```

**Verification:**

```bash
# Trigger a test alert — create a non-system cluster-admin binding
kubectl create sa test-sa -n default
kubectl create clusterrolebinding test-crb --clusterrole=cluster-admin --serviceaccount=default:test-sa

# Check Falco logs
kubectl logs -l app.kubernetes.io/name=falco -n falco | grep "CLUSTER-ADMIN"

# Clean up
kubectl delete clusterrolebinding test-crb
kubectl delete sa test-sa -n default
```

## References

- Falco k8s_audit plugin: https://falco.org/docs/reference/rules/k8s-audit-rules/
- Falco Helm chart: https://github.com/falcosecurity/charts/tree/master/falco
- K8s audit policy reference: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- AWS EKS audit log setup: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- Azure AKS monitoring: https://learn.microsoft.com/en-us/azure/aks/monitor-aks
- GKE audit logging: https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- ATT&CK Containers: "Discovery", "Credential Access", "Privilege Escalation"
- Cross-links: [`../rbac-and-service-account-tokens.md`](../rbac-and-service-account-tokens.md), [`../pod-security-admission-and-psp-replacements.md`](../pod-security-admission-and-psp-replacements.md), [`../labs/kind-escape-lab.md`](../labs/kind-escape-lab.md)
