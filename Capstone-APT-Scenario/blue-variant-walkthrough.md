# 04 — Blue Variant Walkthrough

> **Level:** Advanced
> **Prereqs:** Modules 10–11 + 06
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Detection, Containment, Eradication, Recovery
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

The blue variant operates on the same sandbox as [13-03](./red-variant-walkthrough.md) but with a different objective: detect, contain, and eradicate the red team's killchain, then measure MTTD/MTTR against the SLOs from [11-01](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md). This walkthrough mirrors every red stage with its corresponding blue response.

## The OnPrem reality

A SOC defending on-prem infrastructure would: ingest Windows Event Logs via WinRM/WEF → Splunk/ELK → correlate 4625/4624/4672/4768 events → trigger playbook → isolate VLAN → revoke AD account. The cloud blue variant replaces each primitive: CloudTrail instead of Event Logs, SIEM alert instead of SOC ticket, IAM boundary instead of VLAN isolation.

## Day 0 — Pre-deployment hardening

Before the red lab begins, the blue learner applies preventive controls from Modules 02, 08, and 10. These are deployed *before* the red team starts.

### Cross-cloud preventive control table

| Control | AWS implementation | Azure implementation | GCP implementation | Module ref |
|---|---|---|---|---|
| Block public S3/bucket | SCP denying `s3:PutBucketPublicAccessBlock` with `false` at OU level | Azure Policy deny effect on `storageAccounts.allowBlobPublicAccess=false` | Org Policy `constraints/storage.publicAccessPrevention` = enforced | [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) |
| Deny IAM user creation (enforce SSO) | SCP denying `iam:CreateUser`, `iam:CreateAccessKey` | Azure Policy deny `Microsoft.Authorization/roleAssignments/write` on custom roles | Org Policy `constraints/iam.disableServiceAccountKeyCreation` | [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) |
| Enforce IMDSv2 | SCP denying `ec2:RunInstances` unless `ec2:MetadataHttpTokens=required` | Azure Policy `deployIfNotExists` for IMDS required | Org Policy `constraints/compute.requireOsLogin` + disable legacy metadata | [03-XX](../Compute-Container-Security/) |
| Quarantine IAM boundaries | Permissions boundary attached to all IAM roles (deny all `iam:*` except `Get*`, `List*`) | Azure RBAC custom role without `Microsoft.Authorization/*/write` | IAM custom role without `iam.serviceAccounts.*` write | [02-06](../IAM/permission-boundaries-and-quarantine.md) |
| CI runner least privilege | Replace `AdministratorAccess` with narrower policy: only `lambda:*`, `s3:*` on app bucket | Replace `Owner` with `Contributor` scoped to resource group | Replace `roles/owner` with `roles/cloudfunctions.developer` + `roles/storage.objectAdmin` on app bucket | [08-06](../IaC-Security/cicd-runner-as-cloud-principal.md) |
| Honey-tokens | Inactive IAM access key on `honey-user`, canary S3 object `honey-token.txt`, decoy role `HoneyProdRole` | Inactive SP, canary blob, decoy key vault | Inactive SA key, canary GCS object, decoy SA | [10-04](../Blue-Team-Defense/deception-honeytokens.md) |

### Apply the guardrails (Day 0)

```bash
# AWS — attach SCPs to the sandbox OU
aws organizations attach-policy \
  --policy-id p-scp-denypublics3 \
  --target-id ou-sandbox-xxxxxxxx

aws organizations attach-policy \
  --policy-id p-scp-denyiamuser \
  --target-id ou-sandbox-xxxxxxxx

# Azure — assign deny policies at management group
az policy assignment create \
  --name "deny-public-storage" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/...deny-public-storage..." \
  --scope "/providers/Microsoft.Management/managementGroups/sandbox-mg"

# GCP — set org policies
gcloud org-policies set-policy deny-public-buckets.yaml  # learner crafts
gcloud org-policies set-policy disable-sa-key-creation.yaml
```

### Deploy honey-tokens (Day 0)

```bash
# AWS
aws iam create-user --user-name honey-user
aws iam create-access-key --user-name honey-user  # Never used — alert if touched
aws s3 cp /dev/null s3://capstone-data-111111111111/honey-token.txt

# Azure
az ad sp create-for-rbac --name honey-sp --skip-assignment  # Never assigned — alert if used
az storage blob upload --account-name capstonedataXXXX --container-name public-data \
  --name honey-token.txt --file /dev/null

# GCP
gcloud iam service-accounts create honey-sa
gcloud iam service-accounts keys create /tmp/honey-key.json \
  --iam-account=honey-sa@example-project.iam.gserviceaccount.com
gsutil cp /dev/null gs://capstone-data-example-project/honey-token.txt
```

---

## Day 7 — Detection walkthrough

After Day 0 hardening, the red lab is run. The blue learner monitors the detection pipeline.

### Cross-cloud red-stage-to-blue-detection mapping

| Red stage | AWS detection signal | Azure detection signal | GCP detection signal | Expected alert ID |
|---|---|---|---|---|
| Recon | `s3:ListObjects` from unknown IP on honey-token | `List Blob` on honey blob, Defender alert | `storage.objects.list` on canary object | `CAP-RECON-01` |
| Initial Access (SSRF) | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.Custom` | Defender for Cloud `Suspicious IMDS access` | SCC `compute.instances.serviceAccountCredentialExfiltration` | `CAP-IA-01` |
| Initial Access (leaked key) | CloudTrail `GetCallerIdentity` from external IP | Sign-in log from non-trusted location | `google.iam.credentials.v1.*` from new IP | `CAP-IA-02` |
| Privilege Escalation | GuardDuty `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Defender `Elevated access using service principal` | SCC `Privilege Escalation` finding + Event Threat Detection | `CAP-PE-01` |
| Persistence | `iam:CreateAccessKey` from non-CI IP + `monitoring-service` creation | Role assignment created by recently-compromised SP | `iam.serviceAccountKeys.create` from non-trusted source | `CAP-PER-01` |
| Lateral Movement | `sts:AssumeRole` across 3 distinct account IDs, short window | Cross-subscription RBAC assignment | `serviceAccountTokenCreator` across project boundaries | `CAP-LM-01` |
| Collection | S3 data event volume spike, List/Get ratio > 50:1 | Storage diagnostic log ingress spike | `storage.objects.get` spike > baseline 5x | `CAP-COLL-01` |
| Impact (denied) | CloudTrail `s3:DeleteObject` with `errorCode: AccessDenied` (WORM) | Storage log `Delete Blob` with status 403 + immutability header | `storage.objects.delete` 403 on retention-locked object | `CAP-IMP-01` |

### Detection queries (by red stage)

#### AWS CloudWatch Logs Insights

```sql
-- CAP-IA-01: SSRF → IMDS credential exfiltration
filter eventSource = "ec2.amazonaws.com"
 | filter eventName = "GetCallerIdentity"
 | fields @timestamp, sourceIPAddress, userIdentity.arn
 | filter sourceIPAddress not in ("<trusted-cidr>")
 | sort @timestamp desc

-- CAP-PE-01: PassRole + CreateFunction within 5 min
filter (eventName = "PassRole" or eventName = "CreateFunction")
 | stats count() by userIdentity.arn, eventName
 | filter eventName = "PassRole" and eventName = "CreateFunction"

-- CAP-PER-01: CreateAccessKey by compromised principal
filter eventName = "CreateAccessKey"
 | fields @timestamp, userIdentity.arn, requestParameters.userName
 | filter requestParameters.userName not in ("ci-deployer")
   or userIdentity.type = "AssumedRole"

-- CAP-LM-01: Cross-account AssumeRole chain
filter eventName = "AssumeRole"
 | parse @message '"roleArn":"arn:aws:iam::*"' as targetAccount
 | stats count() by sourceIPAddress, targetAccount
 | filter count >= 2  # 2+ distinct accounts from same IP

-- CAP-COLL-01: List/Get storm on data bucket
filter eventSource = "s3.amazonaws.com"
 | filter eventName in ("ListObjects", "GetObject")
 | stats count() as GetCount by eventName
 | filter (GetCount where eventName="GetObject") > 50 * (GetCount where eventName="ListObjects")

-- CAP-IMP-01: DeleteObject denied by WORM
filter eventName = "DeleteObject" and errorCode = "AccessDenied"
 | fields @timestamp, userIdentity.arn, requestParameters.bucketName, requestParameters.key
```

#### Azure KQL (Sentinel / Log Analytics)

```kusto
// CAP-IA-01: SSRF → IMDS in Azure Activity Log
AzureActivity
| where OperationName == "Microsoft.Compute/virtualMachines/retrieveMetadata/action"
| where CallerIpAddress !in ("<trusted-cidr>")
| project TimeGenerated, Caller, CallerIpAddress, OperationName

// CAP-IA-02: Leaked SP from untrusted IP
SigninLogs
| where AppId == "<ci-deployer-app-id>"
| where Location != "US"  // trusted geo
| project TimeGenerated, UserPrincipalName, IPAddress, Location

// CAP-PE-01: Elevated role assignment by recently-active SP
AzureActivity
| where OperationName == "Microsoft.Authorization/roleAssignments/write"
| where Caller has "ci-deployer"
| join (AzureActivity | summarize LastSeen = max(TimeGenerated) by Caller) on Caller
| project TimeGenerated, Caller, Properties

// CAP-PER-01: New role assignment with Owner
AzureActivity
| where OperationName == "Microsoft.Authorization/roleAssignments/write"
| where Properties contains "Owner"
| project TimeGenerated, Caller, Properties

// CAP-LM-01: Cross-subscription role assignment
AzureActivity
| where OperationName == "Microsoft.Authorization/roleAssignments/write"
| where CallerSubscriptionId != SubscriptionId
| project TimeGenerated, Caller, CallerSubscriptionId, SubscriptionId

// CAP-IMP-01: Delete blob denied by immutability
StorageBlobLogs
| where OperationName == "DeleteBlob"
| where StatusCode == 403
| where AuthenticationErrorDetail contains "ImmutabilityPolicy"
| project TimeGenerated, AccountName, ObjectKey, CallerIpAddress
```

#### GCP Logging queries

```sql
-- CAP-IA-01: SSRF → IMDS credential theft
protoPayload.methodName = "compute.instances.getMetadata"
protoPayload.request.callerSuppliedUserAgent != "GCP Console"
severity >= "WARNING"

-- CAP-IA-02: Leaked SA key from untrusted IP
protoPayload.authenticationInfo.principalEmail = "ci-deployer@example-project.iam.gserviceaccount.com"
protoPayload.requestMetadata.callerIp NOT IN ("<trusted-cidr>")
protoPayload.methodName = "google.iam.credentials.v1.GenerateAccessToken"

-- CAP-PE-01: Token creation abuse (escalation)
protoPayload.methodName = "iam.serviceAccounts.getAccessToken"
protoPayload.authenticationInfo.principalEmail != protoPayload.request.name
-- (principal requesting token != the SA they're impersonating)

-- CAP-PER-01: New service account key creation
protoPayload.methodName = "google.iam.admin.v1.CreateServiceAccountKey"
protoPayload.authenticationInfo.principalEmail != "ci-deployer@example-project.iam.gserviceaccount.com"

-- CAP-LM-01: Cross-project token usage
protoPayload.methodName =~ "storage.objects.*"
protoPayload.resourceName =~ "projects/shared-services-project"
protoPayload.authenticationInfo.principalEmail =~ "*@example-project.iam.gserviceaccount.com"

-- CAP-COLL-01: Storage object read storm
protoPayload.methodName = "storage.objects.get"
protoPayload.resourceName =~ "capstone-data"
-- alert if count > 100 in 5 min window

-- CAP-IMP-01: Delete denied by retention
protoPayload.methodName = "storage.objects.delete"
protoPayload.status.code = 7  -- PERMISSION_DENIED
protoPayload.status.message =~ "retention"
```

---

## Containment, Eradication, Recovery

Follow the IR runbook from [11-01](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md).

### Containment (T+5min after first detection)

| Action | AWS CLI | Azure CLI | GCP CLI | Module ref |
|---|---|---|---|---|
| Deactivate compromised key | `aws iam update-access-key --user-name ci-deployer --access-key-id AKIA... --status Inactive` | `az ad app credential reset --id <app-id> --remove-all` | `gcloud iam service-accounts keys delete <key-id> --iam-account=ci-deployer@...` | [11-05](../IR-Forensics-Cloud/iam-revocation-and-session-physics.md) |
| Attach deny-all inline policy | `aws iam put-user-policy --user-name ci-deployer --policy-name Quarantine --policy-document file://deny-all.json` | `az role assignment delete --assignee <sp-id> --role Owner --scope /subscriptions/...` | `gcloud projects remove-iam-policy-binding example-project --member=... --role=roles/owner` | [11-05](../IR-Forensics-Cloud/iam-revocation-and-session-physics.md) |
| Revoke active sessions | `aws iam update-role --role-name vulnerable-ec2-role --max-session-duration 900` (reduce) | `az rest --method POST --uri "https://graph.microsoft.com/v1.0/users/<obj-id>/revokeSignInSessions"` | `gcloud auth revoke` (invalidates gcloud cached tokens) | [11-05](../IR-Forensics-Cloud/iam-revocation-and-session-physics.md) |
| Snapshot evidence | `aws ec2 create-snapshot --volume-id vol-xxx` | `az snapshot create --resource-group sandbox-rg --name evidence-snap --source <disk-id>` | `gcloud compute disks snapshot <disk-name> --snapshot-names evidence-snap` | [11-04](../IR-Forensics-Cloud/snapshot-and-memory-acquisition.md) |
| Quarantine security group | `aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 0-65535 --cidr 0.0.0.0/0` | `az network nsg rule create --name quarantine --nsg-name sandbox-nsg --priority 100 --access Deny --direction Inbound --protocol '*' --source-address-prefixes '*'` | `gcloud compute firewall-rules create quarantine --network default --action deny --direction ingress --priority 0` | [10-05](../Blue-Team-Defense/auto-response-isolate-and-quarantine.md) |

### Eradication (T+30min)

| Action | AWS | Azure | GCP | Module ref |
|---|---|---|---|---|
| Delete attacker-created principals | `aws iam delete-access-key --user-name monitoring-service --access-key-id AKIA...` + `aws iam delete-user --user-name monitoring-service` | `az ad sp delete --id <monitoring-sp-id>` | `gcloud iam service-accounts delete monitoring-service@...` | [10-08](../Blue-Team-Defense/remediation-automation.md) |
| Delete attacker Lambda | `aws lambda delete-function --function-name capstone-escalate` | `az functionapp delete --name capstone-escalate --resource-group sandbox-rg` | `gcloud functions delete capstone-escalate` | [10-08](../Blue-Team-Defense/remediation-automation.md) |
| Rotate all remaining keys | `aws iam list-access-keys --user-name ci-deployer` × `update-access-key --status Inactive` | `az ad app credential reset --id <app-id>` | `gcloud iam service-accounts keys list --iam-account=ci-deployer@...` × `delete` | [11-05](../IR-Forensics-Cloud/iam-revocation-and-session-physics.md) |
| Fix trust policy | `aws iam update-assume-role-policy --role-name CrossAccountRole-SharedServices --policy-document file://fixed-trust.json` (add `ExternalId` + `aws:PrincipalOrgID`) | Update RBAC assignments to use conditions (`request.tenantId`) | Add IAM conditions (`resource.name.startsWith("projects/example-project")`) | [02-03](../IAM/assume-role-chains-and-trust-graphs.md) |

### Recovery (T+60min)

```bash
# Re-apply IaC baseline (from Module 08-07)
cd sandbox-aws && terraform plan && terraform apply  # drift reconciliation
# Verify posture returns to compliant
prowler aws --region us-east-1 > capstone/post-recovery-scan.json
diff capstone/pre-config-compliance.json capstone/post-recovery-scan.json
```

## 🔴 Red Team view — where blue controls could be bypassed

| Blue control | Bypass technique | Ref to Module 09 lesson |
|---|---|---|
| SCP denying IAM user creation | Compromise an SSO-fed role that `sts:AssumeRole`-s into the org from an external account not covered by the SCP. | [09-06](../Red-Team-Offense/lateral-movement-and-pivoting.md) |
| Honey-token key | Avoid `GetCallerIdentity` — use only `sts:GetFederationToken` (which doesn't trigger the same heuristic). | [09-08](../Red-Team-Offense/evasion-and-trail-free-actions.md) |
| GuardDuty PrivilegeEscalation | Use `iam:UpdateAssumeRolePolicy` to modify a role's trust to include `root` — not flagged by GuardDuty as a dedicated escalation finding (as of June 2026, check current GuardDuty finding coverage for `PrivilegeEscalation:*` findings). | [09-05](../Red-Team-Offense/privilege-escalation-catalogue.md) |
| Cross-account AssumeRole detection | Use `RoleSessionName` matching legitimate automation pattern; stagger across 24 hours. | [09-08](../Red-Team-Offense/evasion-and-trail-free-actions.md) |
| List/Get ratio anomaly | Throttle `GetObject` to 1 object every 6 minutes — matches backup window baseline. | [09-09](../Red-Team-Offense/collection-data-exfil-channels.md) |

Each bypass is a learning opportunity: the blue learner should update the detection rules in [`detections/capstone-detection-pack.md`](./detections/capstone-detection-pack.md) to close these gaps after the initial exercise.

## 🔵 Blue Team view — post-incident metrics

### MTTD / MTTR measurement

| Metric | Definition | Capstone target | Actual (fill in your run) |
|---|---|---|---|
| MTTD (Mean Time to Detect) | Time from first red action to first alert firing | < 15 min | |
| MTTR (Mean Time to Respond) | Time from first alert to containment complete (access revoked) | < 30 min | |
| Scope | Number of accounts/projects compromised | < 3 | |
| Data exfiltrated | Bytes transferred (from logs) | < 1 MB (limited to local stage) | |
| Recovery time | Time from containment to posture restoration | < 60 min | |

### Post-exercise improvement tickets

```
1. [DETECT] Add correlation rule: CreateAccessKey + AssumeRole from same IP within 10 min → Critical.
2. [PREVENT] Add SCP denying iam:PassRole on "*" — scope to specific roles only.
3. [DETECT] Tune List/Get ratio threshold based on actual CI backup traffic baseline.
4. [RESPOND] Automate key deactivation in IR runbook (Lambda/Sentinel Playbook/GCF).
5. [PROCESS] Schedule quarterly purple-team re-run of capstone.
```

## Hands-on lab

Execute [`labs/blue/detect-and-kill-the-apt-lab.md`](./labs/blue/detect-and-kill-the-apt-lab.md) to run the full detection → containment → eradication cycle.

## References

- [13-01 — Architecture Overview](./capstone-architecture-overview.md)
- [13-03 — Red Variant Walkthrough](./red-variant-walkthrough.md)
- [Module 10 — Blue Team Defense](../Blue-Team-Defense/README.md)
- [Module 11 — IR & Forensics](../IR-Forensics-Cloud/README.md)
- [Module 06 — Monitoring & Detection](../Monitoring-Detection-SIEM/README.md)
- [detections/capstone-detection-pack.md](./detections/capstone-detection-pack.md)
- [labs/blue/detect-and-kill-the-apt-lab.md](./labs/blue/detect-and-kill-the-apt-lab.md)
