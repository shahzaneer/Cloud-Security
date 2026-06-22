# 09 — Bicep, ARM & Config Connector Tail

> **Level:** Intermediate
> **Prereqs:** [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md), [08-04 — Policy-as-Code Rego & Sentinel](./policy-as-code-rego-sentinel.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Persistence, Privilege Escalation
> **Authorization scope:** Run deployments and checks against your own sandbox subscriptions/projects only.

## What & why

Not every cloud shop uses Terraform. Azure houses lean toward ARM/Bicep; GCP Kubernetes-native teams use Config Connector CRDs; AWS teams may use CloudFormation or CDK. Every IaC language inherits the same risks: state exposure, plan tampering, misconfiguration drift, and supply-chain trust. This lesson maps the Terraform lessons onto first-party IaC tooling.

## The OnPrem reality

Vendor-locked DSLs existed long before cloud: Cisco IOS config, Juniper `set` commands, F5 iRules. Each had its own syntax, its own footguns, and no cross-platform portability. Cloud-native IaC languages (Bicep, CloudFormation) follow the same pattern — learn their security quirks specifically, don't assume Terraform patterns map 1:1.

## Feature parity map

| Capability | Terraform | Bicep (Azure) | CloudFormation (AWS) | Config Connector (GCP) |
|---|---|---|---|---|
| Declarative syntax | HCL | Bicep DSL (transpiles to ARM) | JSON / YAML | Kubernetes CRD YAML |
| State management | State file (backend) | No — ARM deployment history | Stack state (AWS-managed) | K8s etcd (CRD status) |
| Plan / preview | `terraform plan` | `az deployment group what-if` | `Changeset` | `kubectl diff` |
| Policy-as-code | Sentinel / OPA | Azure Policy `deny` effect | CloudFormation Guard / Hooks | GCP Org Policy + Gatekeeper |
| Drift detection | `terraform plan` | Azure Policy compliance scan | Drift detection (CloudFormation) | Controller reconcile loop |
| Provider ecosystem | ~3,000+ providers | Azure-only | AWS-only | GCP-only |
| Supply chain | `.terraform.lock.hcl` | Bicep module registry (AVM) | CloudFormation registry | K8s OCI images |

## AWS CloudFormation (for comparison)

```yaml
# CloudFormation — state is AWS-managed, no backend config needed
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  LogBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: "logs-bucket-111111111111"
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: alias/aws/s3
```

```bash
# CloudFormation change set (equivalent to terraform plan)
aws cloudformation create-change-set \
  --stack-name prod-logs \
  --template-body file://template.yaml \
  --change-set-name preview

aws cloudformation describe-change-set \
  --change-set-name preview \
  --query "Changes[].ResourceChange"

# Drift detection
aws cloudformation detect-stack-drift --stack-name prod-logs
aws cloudformation describe-stack-resource-drifts --stack-name prod-logs
```

## Azure — Bicep

Bicep is Azure's domain-specific language that transpiles to ARM JSON. It has no state file — deployment history lives in Azure's deployment records. Security advantage: no state file to leak. Security disadvantage: secrets in parameter files or `secure()` parameters can still appear in deployment logs.

```bicep
// main.bicep — secure storage account with diagnostic settings
param location string = resourceGroup().location
param storageAccountName string

@secure()
param adminPassword string  // @secure() suppresses from logs/output

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        blob: { enabled: true }
        file: { enabled: true }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Diagnostic settings — send logs to Log Analytics
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'default'
  scope: stg
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'StorageRead'
        enabled: true
      }
      {
        category: 'StorageWrite'
        enabled: true
      }
      {
        category: 'StorageDelete'
        enabled: true
      }
    ]
  }
}

output storageEndpoint string = stg.properties.primaryEndpoints.blob
```

```bash
# Bicep security workflow
az bicep build --file main.bicep          # transpile → ARM JSON + lint
az bicep lint --file main.bicep           # built-in security rules

# What-if deployment (equivalent to terraform plan)
az deployment group what-if \
  --resource-group rg-prod \
  --template-file main.bicep \
  --parameters adminPassword='placeholder-not-real'

# Deploy with complete mode (deletes resources not in template — like terraform destroy for untracked)
az deployment group create \
  --resource-group rg-prod \
  --template-file main.bicep \
  --mode Complete  # ⚠️ USE WITH CAUTION: deletes anything not in template
```

**Bicep security-specific settings:**

| Mitigation | Bicep syntax | Equivalent Terraform |
|---|---|---|
| Suppress parameter from logs | `@secure()` | `sensitive = true` (variable) |
| Deny public blob access | `allowBlobPublicAccess: false` | `aws_s3_bucket_public_access_block` |
| Enforce HTTPS | `supportsHttpsTrafficOnly: true` | `aws_s3_bucket` (default) |
| Encryption at rest | `encryption.services.blob.enabled: true` | `aws_s3_bucket_server_side_encryption_configuration` |
| Diagnostic settings | `Microsoft.Insights/diagnosticSettings` | `aws_cloudtrail` + `aws_s3_bucket_logging` |

**Bicep linter rules (security):**

```bash
az bicep lint --file main.bicep
# Flags:
#   - no-hardcoded-secrets (catches plaintext passwords in params)
#   - secure-parameter-default (params defaulting to insecure values)
#   - outputs-should-not-contain-secrets
```

**Bicep supply chain — modules:**

```bicep
// Pin Azure Verified Modules by version (not latest)
module avm_storage 'br/public:avm/res/storage/storage-account:0.2.0' = {
  name: 'avm-storage-deployment'
  params: {
    name: storageAccountName
    location: location
  }
}
```

## GCP — Config Connector

Config Connector maps GCP resources to Kubernetes CRDs. The etcd database is the state store; the controller loop is the reconciliation engine.

```yaml
# storage-bucket.yaml — GCP Cloud Storage via Config Connector
apiVersion: storage.cnrm.cloud.google.com/v1beta1
kind: StorageBucket
metadata:
  name: prod-logs-bucket
  annotations:
    cnrm.cloud.google.com/force-destroy: "false"
    cnrm.cloud.google.com/project-id: "my-project-id"
    cnrm.cloud.google.com/management-conflict-prevention-policy: "resource"
spec:
  location: us-central1
  storageClass: STANDARD
  uniformBucketLevelAccess: true
  publicAccessPrevention: enforced
  encryption:
    kmsKeyRef:
      name: bucket-encryption-key
---
# KMS key for bucket encryption
apiVersion: kms.cnrm.cloud.google.com/v1beta1
kind: KMSCryptoKey
metadata:
  name: bucket-encryption-key
spec:
  keyRingRef:
    name: prod-keyring
  purpose: ENCRYPT_DECRYPT
  rotationPeriod: 7776000s  # 90 days
---
# IAM policy — only allow Config Connector's service account to manage
apiVersion: iam.cnrm.cloud.google.com/v1beta1
kind: IAMPolicyMember
metadata:
  name: bucket-admin-binding
spec:
  member: "serviceAccount:config-connector@my-project-id.iam.gserviceaccount.com"
  role: roles/storage.admin
  resourceRef:
    apiVersion: storage.cnrm.cloud.google.com/v1beta1
    kind: StorageBucket
    name: prod-logs-bucket
```

```bash
# Apply the CRD
kubectl apply -f storage-bucket.yaml

# Check status (was the bucket created in GCP?)
kubectl get storagebucket prod-logs-bucket -o yaml
# status.conditions:
#   - type: Ready
#     status: "True"

# Drift detection — diff desired vs live
kubectl diff -f storage-bucket.yaml

# If someone manually changed the bucket in GCP console:
# Config Connector will auto-reconcile (default) or alert (if conflict-prevention-policy: resource)
kubectl describe storagebucket prod-logs-bucket
# Events: "Update call failed: management conflict — resource was modified externally"
```

**Config Connector security patterns:**

| Concern | Config Connector approach |
|---|---|
| State storage | K8s etcd — encrypt with KMS, restrict `kubectl` access |
| Drift reconciliation | Controller auto-reverts (default) or halts with error if `management-conflict-prevention-policy: resource` |
| Secret handling | Never store secrets in CRD YAML — use `Secret` references or External Secrets Operator |
| Audit trail | GCP Cloud Audit Logs + K8s audit logs (two layers) |
| Access control | K8s RBAC (`kubectl auth can-i`) + GCP IAM (service account) |

## 🔴 Red Team view

**Bicep: Insecure default parameters.**

Bicep parameters can have default values. If a module author provides an insecure default (e.g., `networkAcls defaultAction = 'Allow'`), every consumer who doesn't explicitly override it gets the insecure config.

```bicep
// BAD: Insecure default in a shared module
param defaultAction string = 'Allow'  // Anyone deploying this module gets Allow by default

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-01-01' = {
  name: nsgName
  properties: {
    securityRules: [
      {
        name: 'denyAllInbound'
        properties: {
          access: defaultAction  // ← uses the parameter default
          direction: 'Inbound'
          // ...
        }
      }
    ]
  }
}
```

**Contained attacker workflow:**
1. Attacker reviews internal Bicep module registry (or the repo).
2. Finds a shared module with insecure default.
3. Searches for deployments using that module (via Azure Resource Graph): `where properties.templateHash == '<known-module-hash>'`
4. Identifies production VNets with `Allow` default — exfiltration and lateral movement possible.

**Config Connector: Manual CRD mutation bypassing policy.**

1. Attacker gets `kubectl` access to the Config Connector cluster (via compromised pod or leaked kubeconfig).
2. Edits a CRD directly: `kubectl edit storagebucket prod-logs-bucket` → changes `publicAccessPrevention: enforced` to `publicAccessPrevention: inherited`.
3. Config Connector controller immediately reconciles this to GCP — the bucket becomes publicly accessible.
4. No GCP audit log shows the "attacker" — it shows the Config Connector service account as the actor.

**Artifacts:**
- K8s audit log: `kubectl edit` or `kubectl patch` on the CRD
- GCP Cloud Audit Log: `storage.buckets.update` by Config Connector service account (not the attacker's human identity)
- Azure Activity Log: deployment with a specific Bicep module hash

## 🔵 Blue Team view

**Bicep defenses:**

1. **Bicep linter with custom rules:**
   ```bash
   # bicepconfig.json — custom linter rules in repo root
   {
     "analyzers": {
       "core": {
         "verbose": true,
         "rules": {
           "no-hardcoded-env-urls": { "level": "error" },
           "secure-parameter-default": { "level": "error" },
           "no-unnecessary-dependson": { "level": "warning" }
         }
       }
     }
   }
   ```

2. **Azure Policy to audit Bicep deployments:**
   ```json
   {
     "properties": {
       "displayName": "Audit storage accounts without secure transfer",
       "policyRule": {
         "if": {
           "field": "type",
           "equals": "Microsoft.Storage/storageAccounts"
         },
         "then": {
           "effect": "auditIfNotExists",
           "details": {
             "type": "Microsoft.Storage/storageAccounts",
             "existenceCondition": {
               "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
               "equals": "true"
             }
           }
         }
       }
     }
   }
   ```

3. **Require `@secure()` on all password/key parameters — CI gate:**
   ```bash
   # Block Bicep files with plaintext password parameters
   grep -rn "param.*password.*string" . --include="*.bicep" | \
     grep -v "@secure()" && \
     echo "ERROR: password parameters without @secure()" && exit 1
   ```

**Config Connector defenses:**

1. **K8s RBAC — restrict CRD mutation:**
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: config-connector-readonly
   rules:
   - apiGroups: ["storage.cnrm.cloud.google.com"]
     resources: ["storagebuckets"]
     verbs: ["get", "list", "watch"]  # No create/update/patch/delete
   ```

2. **K8s audit log alert on unauthorized CRD mutation:**
   ```yaml
   # Falco rule: detect non-authorized StorageBucket edits
   - rule: ConfigConnector CRD mutated by non-admin
     desc: Detect manual CRD updates outside GitOps pipeline
     condition: >
       ka.target.resource == "storagebuckets" and
       ka.target.subresource == "" and
       ka.verb in (update, patch) and
       not ka.user.username startswith "system:serviceaccount:cnrm-system:"
     output: "Config Connector CRD mutated by %ka.user.name"
     priority: CRITICAL
   ```

3. **GitOps reconciliation — Flux/Argo auto-reverts manual changes:**
   ```yaml
   # ArgoCD — auto-sync ensures Git is source of truth
   apiVersion: argoproj.io/v1alpha1
   kind: Application
   spec:
     syncPolicy:
       automated:
         prune: true
         selfHeal: true  # Reverts any manual CRD changes within 3 minutes
   ```

**Detection checklist:**
- [ ] Bicep linter runs in CI with `no-hardcoded-secrets` and `secure-parameter-default` rules
- [ ] Azure Policy assignments audit all Bicep-managed subscriptions
- [ ] Bicep module registry pinned to AVM versions (not `latest`)
- [ ] Config Connector `management-conflict-prevention-policy: resource` on production CRDs
- [ ] K8s RBAC limits CRD mutations to GitOps service account only
- [ ] Falco / audit log alert on manual CRD edits
- [ ] ArgoCD / Flux selfHeal enabled on Config Connector Application

## Hands-on lab

1. Bicep linter and what-if:
   ```bash
   mkdir lab-bicep && cd lab-bicep
   az bicep install  # if not already installed

   cat > main.bicep <<'EOF'
   param location string = resourceGroup().location
   param storageAccountName string = 'labstore${uniqueString(resourceGroup().id)}'

   param adminPassword string  // Missing @secure() — linter will flag

   resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
     name: storageAccountName
     location: location
     kind: 'StorageV2'
     sku: { name: 'Standard_LRS' }
     properties: {
       allowBlobPublicAccess: false
       supportsHttpsTrafficOnly: true
     }
   }
   EOF

   az bicep lint --file main.bicep
   # Expected: warning about adminPassword missing @secure()
   ```

2. Fix the finding:
   ```bash
   # Replace 'param adminPassword string' with '@secure() param adminPassword string'
   sed -i '' 's/param adminPassword string/@secure()\nparam adminPassword string/' main.bicep
   # (note: sed syntax may vary by shell; the above uses BSD sed (-i '') on macOS; on Linux use -i without '')

   az bicep lint --file main.bicep
   # Expected: no security warnings
   ```

3. What-if deployment (no actual deploy — preview only):
   ```bash
   az deployment group what-if \
     --resource-group sandbox-rg \
     --template-file main.bicep \
     --parameters adminPassword='placeholder-NOT-A-REAL-PASSWORD'
   # Shows what would change — no resources actually created
   ```

4. Config Connector simulation (requires K8s cluster with Config Connector):
   ```bash
   # Apply a bucket CRD and check reconciliation
   kubectl apply -f storage-bucket.yaml
   kubectl wait --for=condition=Ready storagebucket/prod-logs-bucket --timeout=60s

   # Simulate manual drift via gcloud CLI (outside Config Connector)
   gcloud storage buckets update gs://prod-logs-bucket \
     --public-access-prevention=inherited

   # Wait for controller reconciliation (auto-revert)
   sleep 30
   gcloud storage buckets describe gs://prod-logs-bucket \
     --format="json(iamConfiguration.publicAccessPrevention)"
   # Expected: "enforced" — controller auto-reverted the drift
   ```

5. **Teardown:**
   ```bash
   kubectl delete -f storage-bucket.yaml  # For Config Connector resources
   az group delete --name sandbox-rg --yes --no-wait  # For Bicep lab
   ```

## References

- [Bicep Documentation — Security](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/security)
- [Bicep Linter Rules](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/linter)
- [GCP Config Connector](https://cloud.google.com/config-connector/docs/overview)
- [AWS CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)
- [CloudFormation Drift Detection](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/detect-drift-stack.html)
- [Azure Verified Modules](https://azure.github.io/Azure-Verified-Modules/)
- See ATT&CK: T1610 (Deploy Container), T1578 (Modify Cloud Compute Infrastructure)
- [08-01 — IaC State & Backend Security](./iac-state-and-backend-security.md)
- [08-04 — Policy-as-Code Rego & Sentinel](./policy-as-code-rego-sentinel.md)
