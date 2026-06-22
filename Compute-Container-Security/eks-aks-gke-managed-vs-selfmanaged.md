# 10 — EKS / AKS / GKE Managed vs Self-Managed

> **Level:** Intermediate
> **Prereqs:** [K8s Attack Surface Overview](k8s-attack-surface-overview.md) (K8s Attack Surface Overview)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Privilege Escalation, Credential Access, Persistence (see ATT&CK Containers matrix)
**Authorization scope:** Cloud commands use placeholder subscription/account IDs. OnPrem examples target your own self-managed lab cluster. No enumeration of real cloud tenants.

## What & why

Managed Kubernetes (EKS, AKS, GKE) splits the operational burden: the cloud provider manages the control plane (API server, etcd, controller manager, scheduler), and you manage the data plane (worker nodes, pods, networking). Self-managed K8s means you own every layer — including etcd encryption, API server hardening, and audit log shipping. Understanding exactly where the boundary lies in each cloud determines what you must harden vs what the provider hardens for you. Misunderstanding this boundary leads to unmonitored control plane access and blind spots.

## The OnPrem reality

Self-managed Kubernetes — whether on bare metal or VMs — requires the operator to provision, secure, upgrade, and monitor the full stack. etcd must be manually encrypted at rest via KMS plugin; API server audit logs must be collected and shipped to a SIEM; the control plane VMs need OS hardening. This is the hardest operational model and the most common attack path in on-prem compromises (unpatched kube-apiserver, plaintext etcd).

## Core concepts

### Responsibility split matrix

```
Layer                          Managed K8s              Self-Managed
────────────────────────────────────────────────────────────────
Control plane OS               Provider                 You
API server                     Provider (managed)       You
etcd                           Provider (encrypted)     You (encrypt manually)
Controller manager / scheduler Provider                 You
Node OS                        You                      You
kubelet                        You                      You
Container runtime              You                      You
Network plugin (CNI)           Provider default / You   You
Admission controllers          You                      You
Secrets encryption             Provider (opt-in/opt-out)You
Audit logs                     Provider (enable)        You (install fluend/fluentbit)
Node IAM / identity            You                      N/A (on-prem)
```

### Attack implications of the split

| Compromised component | Managed K8s Impact | Self-Managed Impact |
|---|---|---|
| etcd | Read/write all cluster state; provider-managed so harder to reach directly | Full control plane takeover; all Secrets plaintext if no encryption |
| API server | All cluster mutating operations; provider responsibility to patch | Full cluster compromise |
| kubelet | Pod/container escape on that node; logs, exec access | Same + potential pivot to control plane if co-located |
| Node OS | Node compromise; access to all pods on that node | Same + potential pivot to control plane network |
| Node IAM role (AWS/Azure/GCP) | Cross-cloud pivot from K8s to cloud API | N/A |
| CI/CD pipeline | Malicious image pushed, cluster admin token leaked | Same |

## AWS (EKS)

**Responsibility split:**
- AWS manages: control plane VMs, API server, etcd (encrypted at rest with AWS KMS), controller manager, scheduler.
- You manage: worker nodes (AMI patching), kubelet config, container runtime, CNI (AWS VPC CNI is default), admission controllers, secrets encryption (must enable KMS envelope), audit logs (must enable CloudWatch).
- AWS-managed etcd is not directly accessible. API server endpoint is public or private (your choice).

**Minimal Terraform EKS with control plane logging and audit:**

```hcl
# AWS — EKS cluster with audit logging enabled
resource "aws_eks_cluster" "secure" {
  name     = "cluster-sec"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.cluster.id]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
}
```

**Enable audit log delivery to CloudWatch (CLI):**

```bash
# AWS
aws eks update-cluster-config \
  --name cluster-sec \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

**EKS control plane logging gotchas:**
- Audit logs are NOT enabled by default. You must opt in.
- CloudWatch Logs charges apply per GB ingested.
- The audit log format is K8s-native (not CloudTrail format) — use CloudWatch Logs Insights for queries.
- K8s audit policy is managed by AWS — you cannot customize the audit policy (which resources/verbs to log).

**Node IAM role — the cross-cloud pivot point:**

```hcl
# AWS — node IAM role (the critical credential plane)
resource "aws_iam_role" "eks_node" {
  name = "eks-node-secure"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ])
  role       = aws_iam_role.eks_node.name
  policy_arn = each.value
}
```

## Azure (AKS)

**Responsibility split:**
- Azure manages: control plane VMs, API server, etcd (encrypted at rest automatically), controller manager, scheduler.
- You manage: worker nodes, kubelet, runtime, CNI (Azure CNI or kubenet), admission controllers, secrets encryption (KMS envelope optional), diagnostic settings (must enable).
- AKS control plane is free (you pay only for nodes). etcd is not directly accessible.

**Minimal Terraform AKS with audit logging:**

```hcl
# Azure — AKS cluster with audit logging enabled
resource "azurerm_kubernetes_cluster" "secure" {
  name                = "cluster-sec"
  location            = azurerm_resource_group.sec.location
  resource_group_name = azurerm_resource_group.sec.name
  dns_prefix          = "cluster-sec"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }

  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
  }
}

# Azure — enable kube-audit diagnostic logs
resource "azurerm_monitor_diagnostic_setting" "aks_audit" {
  name               = "aks-audit-logs"
  target_resource_id = azurerm_kubernetes_cluster.secure.id

  log_analytics_workspace_id = azurerm_log_analytics_workspace.sec.id

  enabled_log {
    category = "kube-audit"
  }
  enabled_log {
    category = "kube-audit-admin"
  }
  enabled_log {
    category = "kube-apiserver"
  }
}
```

**AKS control plane logging gotchas:**
- kube-audit and kube-audit-admin are separate log categories — enable both.
- Log Analytics workspace charges apply per GB ingested + per GB stored.
- AKS automatically enables RBAC with AAD integration (if configured) but does not force it.

**Node managed identity — the cross-cloud pivot point:**

```hcl
# Azure — use UserAssigned identity for nodes (least privilege)
resource "azurerm_user_assigned_identity" "aks_node" {
  name                = "aks-node-identity"
  resource_group_name = azurerm_resource_group.sec.name
  location            = azurerm_resource_group.sec.location
}

# Attach to node pool
resource "azurerm_kubernetes_cluster_node_pool" "secure_nodes" {
  kubernetes_cluster_id = azurerm_kubernetes_cluster.secure.id
  name                  = "securepool"
  vm_size               = "Standard_D2s_v3"
  node_count            = 2
  mode                  = "System"

  node_labels = { "security" = "production" }
}
```

## GCP (GKE)

**Responsibility split:**
- GCP manages: control plane VMs, API server, etcd (encrypted by default, application-layer secrets encryption enabled by default), controller manager, scheduler.
- You manage: worker nodes, kubelet, runtime, CNI (GKE default or Cilium dataplane v2), admission controllers.
- GKE is the most managed out-of-box: control plane audit logging enabled by default in Cloud Audit Logs; Shielded Nodes enabled by default; secrets encryption at the application layer is default.

**Minimal Terraform GKE with audit logging (already default):**

```hcl
# GCP — GKE cluster (audit logging on by default)
resource "google_container_cluster" "secure" {
  name     = "cluster-sec"
  location = "us-central1-a"

  enable_shielded_nodes = true

  workload_identity_config {
    workload_pool = "my-sandbox-project.svc.id.goog"
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS", "APISERVER"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS", "APISERVER"]
  }

  node_config {
    machine_type = "e2-medium"
    service_account = google_service_account.gke_node.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
```

**GKE control plane logging gotchas:**
- Audit logs are on by default, but you pay for Cloud Logging storage beyond the free tier.
- Unlike EKS/AKS, the GKE audit logging level is NOT configurable — GCP sets a baseline level.
- Binary Authorization (image signing enforcement) is a separate opt-in feature.

**Node service account — the cross-cloud pivot point:**

```hcl
# GCP — node service account (must be least-privilege)
resource "google_service_account" "gke_node" {
  account_id   = "gke-node-sa"
  display_name = "GKE node service account"
}

resource "google_project_iam_member" "node_logging" {
  project = "my-sandbox-project"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}

resource "google_project_iam_member" "node_metrics" {
  project = "my-sandbox-project"
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}
```

## OnPrem (self-managed)

**Everything is your responsibility.** kubeadm-based cluster with manual etcd encryption and audit logging.

**kubeadm config with audit enabled:**

```yaml
# OnPrem — kubeadm-init.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.0
apiServer:
  extraArgs:
    audit-log-path: /var/log/kubernetes/audit.log
    audit-log-maxage: "30"
    audit-log-maxbackup: "10"
    audit-log-maxsize: "100"
    audit-policy-file: /etc/kubernetes/audit-policy.yaml
    encryption-provider-config: /etc/kubernetes/encryption-config.yaml
    anonymous-auth: "false"
    authorization-mode: Node,RBAC
  certSANs:
    - api.internal.example.com
etcd:
  local:
    extraArgs:
      listen-client-urls: https://0.0.0.0:2379
      cert-file: /etc/kubernetes/pki/etcd/server.crt
      key-file: /etc/kubernetes/pki/etcd/server.key
```

**OnPrem encryption at rest config:**

```yaml
# OnPrem — encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: my-kms-plugin
          endpoint: unix:///var/run/kmsplugin/socket.sock
          cachesize: 1000
      - identity: {}
```

**OnPrem audit log shipping (fluent-bit):**

```
# OnPrem — fluent-bit pipeline to ship audit logs to SIEM
[INPUT]
    Name          tail
    Path          /var/log/kubernetes/audit.log
    Tag           kube-audit
    Parser        json

[OUTPUT]
    Name          opensearch
    Match         kube-audit
    Host          opensearch.internal.example.com
    Port          443
    Index         kube-audit
    tls           On
```

## OnPrem mapping (recap table)

| Concern | OnPrem (self-managed) | AWS (EKS) | Azure (AKS) | GCP (GKE) |
|---|---|---|---|---|
| Control plane management | You provision, patch, scale | AWS managed | Azure managed | GCP managed |
| etcd access | Direct (if compromised) | No direct access | No direct access | No direct access |
| etcd encryption | Manual via `--encryption-provider-config` | KMS envelope (must enable) | Automatic at rest; KMS opt-in | Application-layer enabled by default |
| API server audit logs | Manual via `--audit-log-path` + self-ship | CloudWatch (must enable) | Azure Monitor diagnostic (must enable) | Cloud Audit Logs (default) |
| Audit log format | K8s native | K8s native (CloudWatch) | K8s native (Log Analytics) | Cloud Audit Log format (enriched) |
| Node OS hardening | Your responsibility | Your responsibility (Bottlerocket recommended) | Your responsibility (Azure Linux recommended) | Your responsibility (COS recommended) |
| Node identity to cloud | N/A | IAM instance profile (IRSA for pods) | Managed identity (Workload Identity for pods) | Service account (Workload Identity Federation for pods) |
| Cluster upgrade | Manual (`kubeadm upgrade plan`) | AWS managed (control plane) + user-managed (nodes) | Azure managed (auto-upgrade channels) | GCP managed (auto-upgrade + release channels) |
| RBAC + IAM integration | K8s RBAC only (or LDAP) | aws-auth ConfigMap / EKS access entries | Azure AD + Azure RBAC | GCP IAM + K8s RBAC |
| Managed admission service | None | None (add-on) | Azure Policy for AKS | Policy Controller |

## 🔴 Red Team view

**Attack: Compromise the node IAM role → pivot to cloud control plane**

**Scenario:** An attacker escapes a container to the underlying node. On a managed K8s cluster, the node has an IAM role (AWS) / managed identity (Azure) / service account (GCP) to pull images and write logs. If that role is over-privileged, the attacker accesses the cloud API directly from the node.

### AWS — node IAM role abuse

**Step 1 — Attacker escapes to the EC2 node:**

```bash
# From an escaped container on an EKS node (contained, local lab only)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-node-role
# Returns: AccessKeyId, SecretAccessKey, Token for the node's IAM role
```

**Step 2 — Attacker uses the node's IAM credentials to enumerate S3:**

```bash
# AWS — using the node's credential from within the node
AWS_ACCESS_KEY_ID=<from IMDS> \
AWS_SECRET_ACCESS_KEY=<from IMDS> \
AWS_SESSION_TOKEN=<from IMDS> \
aws s3 ls --region us-east-1
# May succeed if node role has s3:ListAllMyBuckets
```

**Step 3 — Attacker uses IAM role to describe other EC2 instances (lateral reconnaissance):**

```bash
aws ec2 describe-instances --region us-east-1
# Lists all EC2 instances the node role can see — including other EKS nodes
# Attacker can now target other nodes or pivot to cloud resources
```

**Step 4 — Attacker discovers the node role can create access keys:**

```bash
aws iam create-access-key --user-name ci-pipeline-user
# If node role has iam:CreateAccessKey — the attacker creates a persistent backdoor
```

### Azure — managed identity abuse

```bash
# From an escaped container on an AKS node (contained, local lab only)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com"
# Returns: access_token for the node's managed identity

# Enumerate resources:
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/resources?api-version=2021-04-01"
```

### GCP — node service account abuse

```bash
# From an escaped container on a GKE node (contained, local lab only)
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: access_token for the node's GCP service account

# Enumerate GCS buckets:
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=my-sandbox-project"
```

**Artifacts left:**
- AWS CloudTrail: `sts:AssumeRole` for the node role from an unexpected user agent; `s3:ListAllMyBuckets` from an EC2 node that never lists buckets; `iam:CreateAccessKey` from a node role
- Azure Activity Log: GET requests to management API from a node IP; token exchanges to unexpected resource URLs
- GCP Cloud Audit Logs: `storage.buckets.list` from a GCE instance service account that has never called this API
- Node-level: IMDS query logs at `169.254.169.254` (AWS), `169.254.169.254` (Azure), `metadata.google.internal` (GCP) from unexpected processes

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| Node IAM role calling unexpected APIs | CloudTrail / Activity Log / Audit Log | `sts:AssumeRole` from EC2 IP that normally only calls ECR/CloudWatch |
| IMDSv1 call detected on node (vs IMDSv2) | CloudTrail (AWS) | `eventSource = ec2.amazonaws.com, eventName = GetInstanceMetadata`, `version = 1.0` |
| Node credential calling cloud APIs the pod should call via IRSA/WIF | CloudTrail | `userIdentity.arn` is the node role, NOT `userIdentity.arn` with `sts/AssumeRoleWithWebIdentity` |
| Node service account listing storage buckets | GCP audit log | `methodName=storage.buckets.list` from `principalEmail=<node-sa>` |
| Creation of long-lived IAM access keys from a node | CloudTrail | `eventName = CreateAccessKey, sourceIPAddress` matches EKS node IP |
| IMDS request from non-systemd process | Falco | `proc.name not in (kubelet, containerd)` making HTTP to 169.254.169.254 |

**Preventive controls per cloud:**

```bash
# AWS — enforce IMDSv2 (require token, disable v1)
aws ec2 modify-instance-metadata-options \
  --instance-id i-1111111111111111 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# AWS — SCP: deny iam:CreateAccessKey from EC2 role (placeholder)
aws organizations create-policy \
  --name DenyEC2CreateKey \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreateAccessKey","iam:CreateLoginProfile"],"Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:ec2:*:*:instance/*"}}}]}' \
  --type SERVICE_CONTROL_POLICY

# Azure — restrict node managed identity to ACR pull + monitoring only
az role assignment create \
  --assignee <node-identity-principal-id> \
  --role "AcrPull" \
  --scope /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.ContainerRegistry/registries/acrsecexample

# GCP — remove cloud-platform scope from node SA; add only necessary scopes
gcloud container node-pools update default-pool \
  --cluster=cluster-sec --zone=us-central1-a \
  --scopes=logging-write,monitoring-write,storage-ro,https://www.googleapis.com/auth/devstorage.read_only
```

**Detection: CloudWatch Logs Insights — EKS node IAM abuse:**

```
fields @timestamp, sourceIPAddress, eventName, userIdentity.arn, userAgent
| filter userIdentity.arn like /eks-node-/
| filter eventName not in ["GetAuthorizationToken", "BatchGetImage", "DescribeInstances"]
| filter eventName in ["ListBuckets", "CreateAccessKey", "PutObject", "GetObject"]
| sort @timestamp desc
| limit 50
```

**Detection: GCP Log Explorer — GKE node SA abuse:**

```
resource.type="gce_instance"
protoPayload.authenticationInfo.principalEmail="gke-node-sa@my-sandbox-project.iam.gserviceaccount.com"
-protoPayload.methodName=("v1.compute.instances.get" OR "storage.objects.get")
protoPayload.methodName=~"storage.buckets"
```

**Response playbook — node IAM abuse:**
1. Rotate node IAM credentials (AWS: `RevokeSession` on the active token; Azure: rotate managed identity key; GCP: rotate service account key).
2. Cordon the compromised node: `kubectl cordon <node>`.
3. Evacuate pods via IRSA/WIF to ensure they still work without node credentials.
4. Identify the source pod: correlate node IP → audit log → pod creation event.
5. Drain and terminate the node.
6. Review node IAM role and strip all permissions not needed for `ecr:GetAuthorizationToken` + `logs:PutLogEvents` (or equivalents).
7. Implement IRSA (AWS) / Workload Identity (Azure/GCP) for all pods that need cloud access — remove cloud API permissions from the node role entirely.

## Hands-on lab

**Goal:** Deploy three minimal clusters (EKS/AKS/GKE — or use `kind`/`k3d` for the self-managed portion) and compare control plane audit log availability, RBAC, and node IAM surface.

**Steps (for AWS — analogous for Azure/GCP; self-managed portion via `kind`):**

1. **EKS:** Create cluster with audit logging:
   ```bash
   eksctl create cluster --name sec-compare --region us-east-1 --with-oidc
   aws eks update-cluster-config --name sec-compare \
     --logging '{"clusterLogging":[{"types":["api","audit","authenticator"],"enabled":true}]}'
   ```
2. **Verify audit logs in CloudWatch:**
   ```bash
   aws logs describe-log-groups --log-group-name-prefix /aws/eks/sec-compare
   ```
3. **Check node IAM role:** `kubectl -n kube-system get pods -l app.kubernetes.io/name=aws-node -o json | jq '.items[].spec.containers[].env'` — note the node role used for VPC CNI.
4. **Self-managed (kind):** `kind create cluster --name sec-compare-onprem`
5. **Compare:** On `kind`, there is no control plane audit log endpoint (you'd need to `docker exec` into the control-plane node and check `/var/log/kubernetes/audit.log` — absent by default). On EKS, it's in CloudWatch.
6. **Test node IAM access:** Deploy a pod to each cluster. On EKS, exec inside and query IMDS: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`. On `kind`, the node has no cloud IAM.
7. Teardown: `eksctl delete cluster --name sec-compare && kind delete cluster --name sec-compare-onprem`

**Expected output:** Managed cluster has audit logs in cloud-native logging; self-managed does not. Node IAM is present only in managed clusters and represents a cross-cloud pivot path.

## Detection rules & checklists

**CLI audit one-liners:**

```bash
# EKS: verify all control plane log types are enabled
aws eks describe-cluster --name cluster-sec --query "cluster.logging.clusterLogging[].types"

# AKS: verify diagnostic settings
az monitor diagnostic-settings list \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.ContainerService/managedClusters/cluster-sec

# GKE: verify logging configuration
gcloud container clusters describe cluster-sec --zone=us-central1-a \
  --format="json(loggingConfig,monitoringConfig)"

# OnPrem: verify audit log is non-empty (indicates active auditing)
ssh k8s-control-1 'wc -l /var/log/kubernetes/audit.log && tail -1 /var/log/kubernetes/audit.log | jq .'

# EKS: verify secrets encryption is enabled
aws eks describe-cluster --name cluster-sec --query "cluster.encryptionConfig"

# AKS: verify secrets encryption is enabled
az aks show --name cluster-sec --resource-group rg-sec \
  --query "keyVaultNetworkAccess"

# GKE: secrets encryption at application layer is default — verify
gcloud container clusters describe cluster-sec --zone=us-central1-a \
  --format="json(databaseEncryption,secretManagerConfig)"

# EKS: verify IMDSv2 is required (all nodes)
aws ec2 describe-instances \
  --filters "Name=tag:kubernetes.io/cluster/cluster-sec,Values=owned" \
  --query "Reservations[].Instances[].MetadataOptions.HttpTokens" | grep -v required

# Audit node IAM role permissions (AWS)
aws iam get-account-authorization-details --filter Role --query "RoleDetailList[?RoleName=='eks-node-role'].AttachedManagedPolicies"
```

**Managed cluster security checklist:**

- [ ] Control plane audit logging enabled and verified (CloudWatch / Azure Monitor / Cloud Audit Logs).
- [ ] Secrets encryption enabled at the KMS layer (EKS/AKS) or verified as default (GKE).
- [ ] API server endpoint is private-only (or public access is CIDR-restricted).
- [ ] Node IAM role / managed identity / service account has zero cloud API permissions beyond ECR pull + log write (all other access via IRSA/WIF).
- [ ] IMDSv2 required on all nodes (`HttpTokens: required`).
- [ ] Node auto-upgrade enabled (EKS managed node groups / AKS auto-upgrade / GKE release channels).
- [ ] Shielded Nodes / Secure Boot enabled (GKE: default; AKS: opt-in; EKS: Bottlerocket AMI).
- [ ] Cluster RBAC integrated with cloud IAM (EKS access entries / AKS Azure RBAC / GKE IAM).
- [ ] Network policy engine deployed (Calico / Cilium) with default-deny in all namespaces.
- [ ] All pods use IRSA/WIF for cloud API access — never static credentials in Secrets.

## References

- EKS shared responsibility model: https://docs.aws.amazon.com/eks/latest/userguide/security.html
- AKS baseline architecture: https://learn.microsoft.com/en-us/azure/architecture/reference-architectures/containers/aks/baseline-aks
- GKE shared responsibility: https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview
- EKS security best practices: https://aws.github.io/aws-eks-best-practices/security/docs/
- CIS Kubernetes Benchmark (self-managed): https://www.cisecurity.org/benchmark/kubernetes
- K8s audit policy docs: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- ATT&CK Containers: "Credential Access" (cloud instance metadata API), "Privilege Escalation" (node to cloud IAM)
- Cross-links: [`03-05-k8s-attack-surface-overview.md`](k8s-attack-surface-overview.md), [`03-06-rbac-and-service-account-tokens.md`](rbac-and-service-account-tokens.md), [`../IAM/assume-role-chains.md`](../IAM/assume-role-chains.md)
