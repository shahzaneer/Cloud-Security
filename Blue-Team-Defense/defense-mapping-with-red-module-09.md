# 09 — Defense Mapping with Red Module 09

> **Level:** Advanced
> **Prereqs:** Modules 09 + 10 completed
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** All — this is the defensive cross-walk for the entire attack chain.
> **Authorization scope:** This is a reference/mapping lesson. No hands-on attack or defense — analysis and gap assessment only.

## What & why

Every offensive technique in Module 09 maps to at least one defensive control covered in Modules 10, 06, and 02. This lesson provides the canonical cross-walk: red technique → blue control(s) → gap assessment → maturity rating. The goal is a single-page matrix that tells you what you're blind to today.

## How to use this mapping

1. For each row, check if your organization has the listed controls deployed.
2. Rows with zero controls in your environment are highest-priority gaps.
3. Use the "Your SLO" column to set measurable targets (MTTD, MTTR).
4. Reassess quarterly — new red techniques appear; new blue capabilities ship.

## ATT&CK-to-Defense Matrix

### Reconnaissance (TA0043)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| DNS/SaaS fingerprinting (09-02) | CSPM — monitor `ListBuckets` / `ListSubscriptions` from unapproved IPs | 06-05, 10-07 | Medium — recon is hard to prevent |
| Org enumeration via `ListAccounts` | SCP: deny `organizations:ListAccounts` for non-admin roles | 10-02 | Low — easy SCP/Policy fix |
| SSRF to metadata endpoint | Enforce IMDSv2, Azure metadata block, GKE conceal metadata | 02-01 | Medium — legacy AMIs/VMs may use v1 |
| GitHub secret scanning for keys | Git pre-receive hooks + `gitleaks` in CI + repo secret scanning | 10-04, 08-05 | Medium — depends on developer adoption |
| Cloud asset inventory via public APIs | API rate limiting + CloudTrail/Activity Log anomaly detection | 06-02, 06-09 | Low — threshold alerting works well |

### Initial Access (TA0001)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Leaked IAM access key (09-03, 09-04) | Eliminate IAM Users → SSO-only via SCP. Honey tokens in git repos | 10-02, 10-04 | High if IAM users still exist |
| Phishing for cloud credentials (09-03) | Conditional Access: MFA + compliant device + impossible-travel detection | 06-05, 06-09 | Medium — CA coverage must be 100% |
| Public-facing vulnerable service (09-03) | Security Group deny 0.0.0.0/0, WAF, Config rule `INCOMING_SSH_DISABLED` | 10-02, 10-08 | Medium — auto-remediation reduces window |
| CI/CD pipeline compromise (09-03) | OIDC federation for pipeline → cloud auth. No long-lived keys in CI | 02-05, 08-06 | High — pipeline identity is often overprivileged |
| Storage container with public access (09-03) | SCP deny public ACL + `PutPublicAccessBlock` auto-remediation | 10-02, 10-08 | Low — auto-fix eliminates most windows |

### Credential Access (TA0006)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Steal EC2 metadata credentials (09-04) | Enforce IMDSv2 via SCP + Config rule. Hop-limit=1 on EC2 instances | 10-02 | Low — SCP-enforceable |
| Dump `.aws/credentials` from compromised host (09-04) | No long-lived keys allowed (SCP + CSPM). Everything via STS/Managed Identity | 02-01, 10-02 | High if IAM Users have keys |
| Steal CI/CD `.gitlab-ci.yml` secrets (09-04) | Secrets Manager + CI variable masking + OIDC-only auth for runners | 05-02, 08-06 | Medium — legacy CI pipelines hard to refactor |
| `GetSessionToken` with stolen MFA (09-04) | Honey token with `Deny *` policy — any usage alerts instantly | 10-04 | Medium — Honey token coverage may be incomplete |
| Abuse overly permissive trust policy (09-04) | Trust policy audit — `ExternalId` required on all cross-account trusts | 02-03, 10-03 | Medium — trust-roles accumulate over time |

### Privilege Escalation (TA0004)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| `iam:PutRolePolicy` to attach admin (09-05) | Permission boundaries + SCP deny `iam:Put*` for non-security roles | 02-06, 10-02 | Low — permission boundaries are strong |
| `iam:PassRole` to Lambda with admin role (09-05) | SCP deny `iam:PassRole` except to explicit role allow-list | 02-06, 10-02 | Medium — PassRole is often unrestricted |
| `iam:UpdateAssumeRolePolicy` to allow self (09-05) | Permission boundary + SCP deny trust-policy modification | 02-06 | Low — boundary blocks even if policy is updated |
| Azure: add self to Global Admin via PIM (09-05) | PIM: require multi-approver + MFA. Alert on PIM role-assignment changes | 10-06, 02-07 | Medium — misconfigured PIM approvals |
| GCP: enable service and add admin (09-05) | Org policy: deny service enablement without tag. Project-level IAM audit | 10-02, 10-07 | Medium — service enablement is often unrestricted |

### Lateral Movement (TA0008)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Cross-account `sts:AssumeRole` (09-06) | SCP: deny `sts:AssumeRole` outside org. Trust policy requires `ExternalId` + `aws:SourceArn` | 10-02, 10-03 | Medium — legacy trusts may not have conditions |
| VPC peering from compromised to prod (09-06) | SCP: deny `ec2:CreateVpcPeeringConnection` except via Terraform role | 10-02 | Low — SCP-enforceable |
| Shared VPC abuse (09-06) | Restrict shared VPC subnet IAM to host-project admins only | 10-03 | Medium — subnet-level IAM is complex |
| Cross-subscription Azure RBAC (09-06) | Management group policy: deny cross-subscription role assignments | 10-02 | Medium — needs policy at MG level |
| GCP cross-project SA impersonation (09-06) | Org policy: `iam.disableServiceAccountKeyCreation` + deny `iam.serviceAccounts.actAs` | 10-02 | Low — Org policy enforceable |
| Instance metadata as pivot (09-06) | Network segmentation: no route between tiers + IMDSv2 enforced | 10-03 | Medium — east-west is hard in cloud |

### Persistence (TA0003)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Backdoor IAM User (09-07) | SCP: deny `iam:CreateUser`, `iam:CreateAccessKey` org-wide | 10-02 | Low — SCP-enforceable |
| Backdoor role with trust to external account (09-07) | SCP: deny `iam:CreateRole` + `iam:UpdateAssumeRolePolicy` except infra pipeline | 10-02 | Low — SCP + permission boundary |
| Persist via Lambda layer / extension (09-07) | SCP: deny `lambda:PublishLayerVersion` for non-approved roles | 10-02 | Medium — Lambda extension abuse is newer technique |
| Cross-cloud trust backdoor (09-07) | Cloud-to-cloud federation audit. Alert if new SAML/OIDC trust appears | 06-05, 10-01 | Medium — cloud federation blind spot |
| Schedule recurring malicious action (09-07) | CloudTrail `PutRule` audit. EventBridge/CloudWatch rules inventory | 06-02, 10-07 | Low — rule inventory + drift check |
| API key / client secret creation (09-07) | SCP/Org Policy: deny key creation. Regular inventory of all keys | 10-02, 10-04 | Low — Org-policy enforced |

### Evasion (TA0005)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Stop/delete CloudTrail (09-08) | SCP: deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` | 10-02 | Low — SCP-enforceable |
| Disable GuardDuty/Security Hub (09-08) | SCP: deny `guardduty:DeleteDetector`, `securityhub:DisableSecurityHub` | 10-02 | Low — SCP-enforceable |
| Delete flow logs (09-08) | SCP: deny `ec2:DeleteFlowLogs`, Config rule `VPC_FLOW_LOGS_ENABLED` | 10-02 | Low — SCP + drift detection |
| Regions outside monitoring (09-08) | SCP: deny actions outside allow-listed regions | 10-02, 10-07 | Low — SCP-enforceable |
| Abuse instance metadata endpoint v1 (09-08) | IMDSv2 enforcement. Metadata response hop-limit=1 | 10-02 | Medium — depends on legacy application support |
| Use `User-Agent` spoofing to blend (09-08) | UEBA: detect anomalous User-Agent for a given role | 06-09 | Medium — requires mature SIEM/UEBA |

### Collection / Exfiltration (TA0009 / TA0010)

| Red technique (Module 09) | Blue control | Module ref | Gap risk |
|---|---|---|---|
| Exfil to external S3 / Blob / GCS (09-09) | SCP: deny `s3:PutObject` with non-org destination. VPC endpoint policies | 10-02 | Medium — data exfil SCP is broad and may break SaaS integrations |
| Copy database snapshot to external account (09-09) | SCP: deny `rds:ModifyDBSnapshotAttribute`, `rds:CopyDBSnapshot` with external account | 10-02 | Low — API-specific SCPs are effective |
| Exfil via DNS tunneling (09-09) | Route 53 Resolver DNS Firewall + VPC flow log analysis | 06-05, 10-03 | Medium — DNS exfil detection is noisy |
| Share AMI / Compute Image publicly (09-09) | SCP: deny `ec2:ModifyImageAttribute` with public launch permission | 10-02 | Low — SCP-enforceable |
| Exfil via Lambda URL (09-09) | SCP: deny `lambda:CreateFunctionUrlConfig` for non-approved functions | 10-02 | Medium — Lambda URL is newer feature |

## Gap assessment worksheet

For each row above, compute your organization's gap score:

```
Gap = Red technique exists AND Blue control NOT deployed
Coverage = Blue controls deployed / Total possible blue controls
MTTD_SLO = Desired mean-time-to-detect in minutes
MTTR_SLO = Desired mean-time-to-respond in minutes
```

**Example gap assessment for a hypothetical org:**

| Red technique | Controls deployed | Gap? | MTTD SLO | MTTR SLO |
|---|---|---|---|---|
| Leaked IAM access key | Honey tokens, gitleaks in CI, SCP deny CreateAccessKey | Partial — SSO not yet enforced | 10 min | 30 min |
| Cross-account AssumeRole | SCP deny outside org, ExternalId required | Covered | 2 min | 5 min |
| Stop CloudTrail | SCP deny StopLogging/DeleteTrail | Covered | 1 min | 5 min |
| Public S3 bucket | SCP deny public ACL, Config auto-remediation | Covered | 1 min | 3 min (auto) |
| Persist via Lambda extension | No Lambda-specific SCPs | **GAP** | Unknown | Manual |

**Highest-priority gaps (likely for most orgs):**

1. **Lambda extension persistence** — few orgs restrict `lambda:PublishLayerVersion`.
2. **Cross-cloud trust backdoors** — federation audit is manual in many orgs.
3. **CI/CD pipeline as cloud principal** — OIDC migration still in progress.
4. **DNS exfiltration monitoring** — requires VPC DNS Firewall + flow log analysis.
5. **Post-quarantine active STS session abuse** — no revocation possible; must shorten TTL.

## AWS summary — top 10 SCPs from the matrix

| # | SCP | Blocks | Module |
|---|---|---|---|
| 1 | Deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` | Evasion via logging kill | 10-02 |
| 2 | Deny `iam:CreateUser`, `iam:CreateAccessKey` | Persistence via backdoor IAM user | 10-02 |
| 3 | Deny `s3:PutBucketAcl` with public-read | Initial access via public bucket | 10-02 |
| 4 | Deny `sts:AssumeRole` outside org | Lateral movement | 10-03 |
| 5 | Deny `iam:PassRole` except allow-list | Privilege escalation | 10-02 |
| 6 | Deny actions outside allowed regions | Evasion via unmonitored regions | 10-07 |
| 7 | Deny `ec2:CreateVpcPeeringConnection` | Lateral movement | 10-03 |
| 8 | Deny `guardduty:DeleteDetector`, `securityhub:DisableSecurityHub` | Evasion | 10-02 |
| 9 | Deny `ec2:ModifyImageAttribute` public | Exfiltration | 10-02 |
| 10 | Deny `iam:UpdateAssumeRolePolicy` | Privilege escalation | 10-02 |

## Azure summary — top 10 Azure Policies from the matrix

| # | Policy | Blocks | Module |
|---|---|---|---|
| 1 | Deny public blob container creation | Initial access via public storage | 10-02 |
| 2 | Deny subscription move out of management group | Organization escape | 10-01 |
| 3 | Deny diagnostic settings deletion | Evasion | 10-02 |
| 4 | Require MFA for all users | Credential access | 10-02 |
| 5 | Deny VM creation without Azure Monitor agent | Evasion via unmonitored VMs | 10-07 |
| 6 | Deny VNet peering across management groups | Lateral movement | 10-03 |
| 7 | Restrict allowed locations | Evasion via unmonitored regions | 10-02 |
| 8 | Deny App Registration without certificate | Persistence | 10-02 |
| 9 | Deny Key Vault firewall bypass | Exfiltration | 10-02 |
| 10 | Deny classic resources | Attack surface reduction | 10-02 |

## GCP summary — top 10 Org Policies from the matrix

| # | Org Policy constraint | Blocks | Module |
|---|---|---|---|
| 1 | `storage.publicAccessPrevention` | Initial access via public bucket | 10-02 |
| 2 | `iam.disableServiceAccountKeyCreation` | Credential access + persistence | 10-02 |
| 3 | `iam.allowedPolicyMemberDomains` | Lateral movement across orgs | 10-02 |
| 4 | `gcp.resourceLocations` | Evasion via unmonitored regions | 10-02 |
| 5 | `compute.skipDefaultNetworkCreation` | Initial access via default VPC | 10-03 |
| 6 | `compute.restrictSharedVpcSubnetworks` | Lateral movement | 10-03 |
| 7 | `sql.restrictPublicIp` | Initial access via public DB | 10-02 |
| 8 | `compute.vmExternalIpAccess` | Initial access via public VM | 10-03 |
| 9 | `constraints/compute.trustedImageProjects` | Persistence via untrusted images | 10-02 |
| 10 | `storage.uniformBucketLevelAccess` | Initial access via object ACLs | 10-02 |

## 🔴 Red Team view

**Look for "0 defense entries" in the matrix — these are your blind spots.**

A red team operator reviewing this matrix for a client identifies:

- **Lambda extension persistence** has zero SCP coverage in 80% of AWS organizations. An attacker who gets `lambda:UpdateFunctionCode` can backdoor every Lambda in the account via a shared layer.
- **DNS exfiltration** is unmonitored in most orgs because VPC Flow Logs + Route 53 Resolver DNS Firewall requires deliberate opt-in, not default configuration.
- **Cross-cloud federation backdoors** are invisible if the SOC only monitors their primary cloud's logs. An attacker adding a GCP Workload Identity Federation to an AWS IAM trust creates a cross-cloud bridge that doesn't appear in CloudTrail.

**Narrative — gap exploitation (contained):**

An attacker compromises a development AWS account. The account has SCPs blocking CloudTrail disable, IAM user creation, and public S3. The attacker attempts:

1. `iam:CreateUser` → Denied by SCP.
2. `cloudtrail:StopLogging` → Denied by SCP.
3. `s3:PutBucketAcl public-read` → Denied by SCP.
4. `lambda:CreateFunction` → Allowed.
5. `lambda:PublishLayerVersion` → Allowed (no SCP covers this).
6. Attacker publishes a Lambda layer that intercepts all `aws-sdk` calls. Every function importing the attacker's layer now sends a copy of its AWS credentials to the attacker's external endpoint.

The gap: every SCP was deployed *except* `lambda:PublishLayerVersion`. The matrix row for "Lambda extension persistence" has a `Gap = True`.

## 🔵 Blue Team view

**Use gaps to prioritize the hardening backlog.**

**Priority matrix:**

| Priority | Condition | Action |
|---|---|---|
| **P0** | Gap exists + technique has known active exploits + detection impossible | Deploy preventive control this sprint |
| **P1** | Gap exists + technique requires admin-level access to exploit | Detection rule this sprint; preventive next sprint |
| **P2** | Gap exists but technique requires chained vulnerabilities | Add to backlog, monitor threat intel |
| **P3** | Control deployed but not tested quarterly | Schedule quarterly test |

**Controls MTTD/MTTR SLO check cadence:**

| SLO | Metric | Check frequency | Escalation |
|---|---|---|---|
| MTTD < 5 min | Time from CloudTrail event to SOC alert | Weekly automated test (simulate event) | If > 10 min for 2 weeks, escalate to engineering |
| MTTR < 15 min | Time from SOC alert to isolation/quarantine applied | Monthly drill | If > 30 min, post-mortem required |
| Coverage > 90% | Controls deployed / Total Matrix rows | Monthly gap-assessment review | If < 80%, create project in next PI |
| False-positive rate < 5% | Alerts that were closed as false-positive / Total alerts | Weekly alert review | If > 10%, tune detection rules |

**Quarterly defense review script:**

```bash
#!/usr/bin/env bash
echo "=== Defense Matrix Gap Assessment: $(date) ==="

echo "--- AWS SCPs ---"
aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[*].Name' --output table

echo "--- Azure Policies (deny only) ---"
az policy assignment list \
  --query "[?sku.tier=='Standard'].{Name:displayName,Scope:scope}" --output table

echo "--- GCP Org Policies ---"
gcloud org-policies list --organization=000000000000 --format='table(constraint)'

echo "--- Gaps to address ---"
echo "1. Lambda extension SCP"
echo "2. DNS exfiltration monitoring"
echo "3. Cross-cloud federation audit"
```

Cross-link: [09-Red-Team-Offense Module](../Red-Team-Offense/) — all lessons, [10-02 Preventive Guardrails](preventive-guardrails-as-code.md), [10-03 Blast Radius](blast-radius-reduction-patterns.md), [06-09 UEBA Basics](../Monitoring-Detection-SIEM/entity-behaviour-ueba-basics.md).

## Hands-on lab

This is a reference/mapping lesson. Apply the gap-assessment worksheet to your own organization's AWS/Azure/GCP environments. Count deployed controls against the matrix rows and identify the top 3 gaps.

## Detection rules & checklists

**Checklist — quarterly defense review:**
- [ ] All 10 top SCPs deployed in AWS.
- [ ] All 10 top Azure Policies deployed.
- [ ] All 10 top GCP Org Policies deployed.
- [ ] Lambda extension SCP deployed (if not: P0 gap).
- [ ] DNS exfiltration monitoring enabled (Route 53 Resolver DNS Firewall).
- [ ] Cross-cloud federation audit is part of monthly security review.
- [ ] All SCPs tested via CI guardrail-validation job.

## References
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS SCP Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_best-practices.html)
- [Azure Enterprise-Scale Security](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/enterprise-scale/security-governance-and-compliance)
- [GCP Security Foundations Guide](https://cloud.google.com/architecture/security-foundations)
