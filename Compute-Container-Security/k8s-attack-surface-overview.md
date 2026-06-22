# 05 — Kubernetes Attack Surface Overview

> **Level:** Intermediate
> **Prereqs:** [VM Hardening Baseline](vm-hardening-baseline.md) (VM Hardening Baseline)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Execution, Persistence, Privilege Escalation, Discovery, Lateral Movement, Collection, Impact (see ATT&CK Containers matrix)
**Authorization scope:** Run only against a local `kind` cluster you own. All `kubectl` commands target `kind` context only.

## What & why

The Kubernetes attack surface spans every layer of the stack — from the control plane API to the container runtime. Understanding this surface systematically is prerequisite to hardening any managed or self-managed cluster. Each component is independently exploitable and must be locked down individually.

## The OnPrem reality

Before orchestration, containers ran directly on VMs via Docker daemon with no API server, no RBAC, no admission control. Security was the host OS boundary. Kubernetes adds the control plane, etcd, kubelet, and service mesh — each a new trust domain. OnPrem self-managed K8s means you own every layer.

## Core concepts

```
                    ┌──────────────┐
                    │   kubectl    │
                    │  (authenticated)│
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │     API Server          │  ← AuthN, AuthZ, Admission
              │   (kube-apiserver)      │
              └────┬──────────┬─────────┘
                   │          │
        ┌──────────▼──┐  ┌───▼──────────┐
        │    etcd     │  │  kubelet     │
        │ (all state) │  │ (node agent) │
        └─────────────┘  └───┬──────────┘
                             │
                    ┌────────▼────────┐
                    │ Container Runtime│
                    │ (containerd, CRI-O)│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │    Pod / Workload│
                    └─────────────────┘
```

| Surface | What It Exposes | Exploitation Impact |
|---|---|---|
| API server | Cluster-wide mutating endpoint | Full cluster control via RBAC abuse |
| etcd | All cluster state (secrets, config) | Read → all secrets; Write → cluster takeover |
| kubelet | Node-local API (pods, logs, exec) | Node compromise, container escape |
| RBAC | Who can do what | Misbinding → cluster-admin proliferation |
| ServiceAccount tokens | Pod identity inside cluster | Token theft → impersonate workload |
| Admission controllers | Gate on create/update | Bypass → privileged pods, hostPath mounts |
| Container runtime | syscall boundary | Escape via capabilities, CVEs |
| CNI / Network policy | Pod-to-pod traffic | Lateral movement between namespaces |
| Secrets | ConfigMaps, env vars, etcd | Credential dumping |
| Supply chain | Images, charts, operators | Backdoored images / helm charts |

## Cross-cloud managed vs self-managed boundaries

| Component | AWS (EKS) | Azure (AKS) | GCP (GKE) | OnPrem self-managed |
|---|---|---|---|---|
| API server | AWS managed | Azure managed | GCP managed | You manage |
| etcd | AWS managed (encrypted at rest) | Azure managed | GCP managed (encrypted) | You manage (encrypt manually) |
| kubelet | You manage (on node) | You manage (on node) | You manage (on node) | You manage |
| Control plane logging | CloudWatch (enable per cluster) | Diagnostic settings (enable) | Cloud Audit Logs (enabled by default) | Self-collected via fluentd/fluentbit |
| Node OS | Amazon Linux 2 / Bottlerocket | Azure Linux / Ubuntu | Container-Optimized OS / Ubuntu | Your choice |
| CNI | AWS VPC CNI (default) | Azure CNI / kubenet | GKE default CNI | Calico / Cilium (your choice) |
| Admission | You configure | You configure | You configure | You configure |
| Secrets encryption | KMS envelope (enable) | KMS envelope (enable) | Application-layer (enabled by default) | Manual KMS integration |

## AWS (EKS)

**Cluster creation with audit logging enabled:**
```bash
# AWS
aws eks create-cluster \
  --name cluster-sec \
  --role-arn arn:aws:iam::111111111111:role/eks-service-role \
  --resources-vpc-config subnetIds=subnet-1111,subnet-2222 \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

**Enable secrets encryption:**
```bash
# AWS
aws eks associate-encryption-config \
  --cluster-name cluster-sec \
  --encryption-config "[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"arn:aws:kms:us-east-1:111111111111:key/aaaa-1111\"}}]"
```

**Audit node IAM roles (IRSA-ready):**
```bash
# AWS
aws eks describe-nodegroup --cluster-name cluster-sec --nodegroup-name ng-workers \
  --query "nodegroup.nodeRole"
```

## Azure (AKS)

**Cluster creation with audit logging:**
```bash
# Azure
az aks create \
  --resource-group rg-sec \
  --name cluster-sec \
  --enable-audit-logs \
  --enable-azure-rbac \
  --node-count 2 \
  --enable-addons monitoring
```

**Enable secrets encryption (KMS):**
```bash
# Azure
az aks update \
  --resource-group rg-sec \
  --name cluster-sec \
  --enable-encryption-at-host \
  --enable-secret-rotation
```

**Diagnostic settings for control plane logs:**
```bash
# Azure
az monitor diagnostic-settings create \
  --name aks-logs \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-sec/providers/Microsoft.ContainerService/managedClusters/cluster-sec \
  --logs '[{"category":"kube-audit","enabled":true}]' \
  --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/ws-sec
```

## GCP (GKE)

**Cluster creation (audit logging enabled by default):**
```bash
# GCP
gcloud container clusters create cluster-sec \
  --zone=us-central1-a \
  --enable-dataplane-v2 \
  --workload-pool=my-sandbox-project.svc.id.goog \
  --enable-shielded-nodes \
  --logging=SYSTEM,WORKLOAD \
  --monitoring=SYSTEM
```

**Verify audit logging:**
```bash
# GCP
gcloud container clusters describe cluster-sec --zone=us-central1-a \
  --format="json(loggingService,monitoringService)"
```

**Enable workload identity:**
```bash
# GCP
gcloud container node-pools update default-pool \
  --cluster=cluster-sec --zone=us-central1-a \
  --workload-metadata=GKE_METADATA
```

## OnPrem (self-managed)

**kubeadm audit policy (minimal baseline):**
```yaml
# OnPrem
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Request
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "delete", "update", "patch"]
  - level: RequestResponse
    users: ["system:anonymous"]
```

**API server flags for audit logging:**
```bash
# OnPrem
kube-apiserver \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=10 \
  --audit-log-maxsize=100
```

## 🔴 Red Team view

**Attack surface mapping on a local `kind` cluster:**

```bash
# Create local kind cluster
kind create cluster --name target

# 1. API Server — probe anonymous access
kubectl --server=https://127.0.0.1:$(kubectl config view -o json | jq '.clusters[]|select(.name=="kind-target").cluster.server' -r | cut -d: -f3) \
  --insecure-skip-tls-verify --token="" get pods --all-namespaces 2>&1

# 2. kubelet — check if read-only port is exposed (10255)
kubectl get nodes -o wide
# From a pod: curl http://<node-ip>:10255/pods

# 3. RBAC — list cluster-admin bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# 4. ServiceAccount tokens — list default SA secrets
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type=="kubernetes.io/service-account-token") | .metadata.namespace, .metadata.name'

# 5. Pods — find privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace, .metadata.name'

# 6. Network — port-forward to internal service
kubectl port-forward svc/kubernetes 8443:443 --namespace default
```

**Artifacts left:** API server audit logs for anonymous access attempts, kubectl exec/port-forward events, etcd direct-access attempts (if enabled). On managed clusters, these map to CloudTrail/Activity Log/Cloud Audit Logs events.

## 🔵 Blue Team view

**Defense per attack surface:**

| Surface | Control | Tooling |
|---|---|---|
| API server | Disable anonymous auth, enable audit, restrict CIDR | Cloud provider IAM + cluster auth webhook |
| etcd | Encryption at rest (KMS envelope), TLS everywhere | Cloud KMS + `--encryption-provider-config` |
| kubelet | Disable anonymous auth, disable read-only port, enable webhook authZ | Node authorization mode + `--anonymous-auth=false` |
| RBAC | Least-privilege RoleBindings, no default cluster-admin | `kubectl auth can-i --list` per SA audit |
| SA tokens | Projected tokens, short-lived, audience-bound | `--service-account-issuer`, TokenReview API |
| Admission | PSA restricted, Gatekeeper/Kyverno deny privileged | `kubectl label ns default pod-security.kubernetes.io/enforce=restricted` |
| Container runtime | Non-root user, read-only root FS, no new privs | SecurityContext + seccomp profile |
| Network | NetworkPolicy default-deny, namespace isolation | Calico / Cilium NetworkPolicy |
| Secrets | External secrets operator, sealed-secrets | CSI driver + cloud secret store |
| Supply chain | Image signature verification, digest pinning | cosign + admission webhook |

**Audit log query (CloudWatch Logs Insights — EKS):**
```
fields @timestamp, user.username, objectRef.resource, verb
| filter objectRef.resource in ["secrets", "configmaps", "pods/exec"]
| sort @timestamp desc
| limit 50
```

**Node-level check one-liners:**
```bash
# Check kubelet config on any node
ps aux | grep kubelet | tr ' ' '\n' | grep -E 'anonymous-auth|authorization-mode|read-only-port'

# Find pods in kube-system that aren't system components
kubectl get pods -n kube-system -o json | jq -r '.items[] | select(.metadata.labels["app.kubernetes.io/managed-by"]==null) | .metadata.name'
```

## Hands-on lab

**Goal:** Map the attack surface of a local `kind` cluster and apply baseline hardening.

**Steps:**
1. `kind create cluster --name sec-lab`
2. Run each Red Team probe command above; note what succeeds.
3. Check anonymous access: `kubectl --token="" get pods --all-namespaces` — should be denied by default on kind.
4. List all cluster-admin bindings and note any non-system subjects.
5. Check if any pods run as privileged: `kubectl get pods -A -o json | jq '[.items[] | select(.spec.containers[].securityContext.privileged==true)] | length'`.
6. Apply a NetworkPolicy default-deny in the `default` namespace.
7. Attempt to curl the kubelet from within a pod — note the 401.
8. Teardown: `kind delete cluster --name sec-lab`.

**Expected output:** Anonymous access is denied; no unexpected cluster-admin bindings; default namespace has no privileged pods by default on fresh kind.

## Detection rules & checklists

**Falco rule — API server anonymous access:**
```yaml
- rule: Anonymous K8s API Access
  desc: Detect attempts to access API server with no credentials
  condition: >
    ka.user.name="system:anonymous" and ka.target.resource!="healthz"
  output: "Anonymous access to %ka.target.resource (user=%ka.user.name)"
  priority: WARNING
  source: k8s_audit
```

**CLI audit one-liners:**
```bash
# EKS: check if audit logging is enabled
aws eks describe-cluster --name cluster-sec --query "cluster.logging.clusterLogging[].types"

# AKS: check diagnostic settings
az monitor diagnostic-settings list --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.ContainerService/managedClusters/cluster-sec

# GKE: verify logging is enabled
gcloud container clusters describe cluster-sec --zone=us-central1-a --format="json(loggingService)"

# OnPrem: check audit log size (non-empty)
wc -l /var/log/kubernetes/audit.log

# Universal: list pods running in kube-system namespace
kubectl get pods -n kube-system --sort-by=.metadata.creationTimestamp
```

## References
- Kubernetes security documentation: https://kubernetes.io/docs/concepts/security/
- ATT&CK Containers matrix: https://attack.mitre.org/matrices/enterprise/containers/
- EKS security best practices: https://aws.github.io/aws-eks-best-practices/security/docs/
- AKS security baseline: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/aks-security-baseline
- GKE hardening guide: https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
- Cross-links: [`03-01-vm-hardening-baseline.md`](vm-hardening-baseline.md), [`03-06-rbac-and-service-account-tokens.md`](rbac-and-service-account-tokens.md), [`03-07-pod-security-admission-and-psp-replacements.md`](pod-security-admission-and-psp-replacements.md)
