# 04 — Authentication, Authorization & Accountability

> **Level:** Fundamental
> **Prereqs:** 01-shared-responsibility
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Privilege Escalation, Defense Evasion
> **Authorization scope:** Run only in your own sandbox account. Use only placeholder keys (`AKIAIOSFODNN7EXAMPLE`).

## What & why
Most cloud breaches are identity failures — leaked access keys, over-privileged roles, missing MFA. Authentication (who you are), Authorization (what you can do), and Accountability (who did what) must be wired separately in each cloud, or you lose the trail.

## The OnPrem reality
- **AuthN:** Kerberos tickets, Active Directory domain join, LDAP binds. A domain admin owns everything.
- **AuthZ:** NTFS ACLs, group policy objects, sudoers files. File-server share permissions.
- **Accountability:** SIEM ingests Windows Event Log (4624/4625), firewall logs, proxy logs. Correlated manually.

## Core concepts

| Concept | Definition | Cloud nuance |
|---------|------------|-------------|
| **Identity type** | Human / service / workload / machine | Workload = an EC2 instance or pod has identity without a key file |
| **Token vs long-lived key** | Short-lived credentials (STS token, OIDC token) vs never-expiring access keys | Long-lived keys are the #1 cloud breach vector. Prefer tokens. |
| **Just-in-time (JIT) vs standing privilege** | Privilege granted only when needed and for a limited time vs always-on permissions | PIM/PAM systems provide JIT across clouds |
| **RBAC vs ABAC** | Role-Based (assign permissions to roles, attach principals) vs Attribute-Based (conditions on tags, IP, time) | ABAC supplements RBAC; both exist in all three clouds |
| **Auditability** | Every auth decision logged, queryable, immutable | CloudTrail / Activity Log / Cloud Audit Logs are the backbone |

## AWS

**Primitives:**
- **IAM User:** Long-lived human/service identity with access keys or console password.
- **IAM Role:** Short-lived identity assumed by a trusted entity (user, service, account). No static credentials.
- **STS (Security Token Service):** Issues temporary credentials — `AssumeRole`, `GetSessionToken`, `GetFederationToken`.
- **Service-linked role:** Predefined role tied to a specific AWS service (e.g., `AWSServiceRoleForAutoScaling`).
- **Permission boundaries:** Cap the maximum permissions a role can ever have, even if attached policies are over-scoped.
- **Session policies:** Inline policies passed during `AssumeRole` to further restrict the session.

**CLI one-liner — role assumption:**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/ReadOnlyRole \
  --role-session-name audit-session \
  --external-id 'placeholder-external-id'
```

**Gotcha:** IAM roles attached to EC2 are available to any process on the instance via IMDS. If you can curl IMDS, you *are* the role. No MFA possible on instance roles.

## Azure

**Primitives:**
- **Entra ID (formerly Azure Active Directory):** The identity plane. Users, groups, service principals, managed identities.
- **Managed Identity:** Azure's equivalent of IAM instance roles — no key to store. System-assigned (tied to resource lifecycle) or user-assigned.
- **Service principal:** An application identity — used for automated tools. Has a client secret or certificate.
- **RBAC scopes:** Management group → subscription → resource group → resource. Permissions inherit downward.
- **Conditional Access:** Policy engine — if user is outside trusted IP, require MFA or block entirely.

**CLI one-liner — managed identity token fetch:**
```bash
az account get-access-token --resource https://management.azure.com/
# Or from within a VM:
curl -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
```

**Gotcha:** A contributor on a subscription can escalate to Owner by creating a role assignment. This is by design — the "Contributor" role includes `Microsoft.Authorization/roleAssignments/write`.

## GCP

**Primitives:**
- **IAM:** Not users-first — permissions are granted on resources via bindings. `roles/` are predefined or custom.
- **Service account:** Both an identity and a resource. Can be impersonated by users or other SAs.
- **Workload Identity:** Maps a Kubernetes service account to a GCP service account (GKE). No key file needed.
- **IAM Conditions:** Attribute-based — grant `roles/storage.admin` only if `resource.name.startsWith('projects/_/buckets/prod-')`.
- **Workforce Identity Federation:** Map external IdP (Okta, Entra ID) to GCP roles without creating GCP user accounts.

**CLI one-liner — impersonate service account:**
```bash
gcloud auth application-default login --impersonate-service-account \
  sa-example@project-id.iam.gserviceaccount.com
```

**Gotcha:** Service account keys (.json files) are the GCP equivalent of long-lived AWS access keys. They never expire by default.

## Recap table

| Identity primitive | AWS | Azure | GCP |
|--------------------|-----|-------|-----|
| Human user | IAM User (or SSO via Identity Center) | Entra ID user (or external guest) | Cloud Identity user (or Workforce Identity Federation) |
| Machine/service identity | IAM Role, IAM User w/ access key | Service Principal, Managed Identity | Service Account |
| Temporary credentials | STS `AssumeRole` (1hr default, max 12hr) | Managed Identity tokens, Entra ID tokens (1hr) | Short-lived SA credentials, OAuth2 access tokens (1hr) |
| Policy language | JSON IAM policy (Effect, Action, Resource, Condition) | Azure RBAC role definitions (JSON) | IAM bindings (YAML/JSON), IAM Conditions (CEL-based) |
| Permission boundary | Permission boundaries, SCPs | Management group hierarchy + Azure Policy | Resource hierarchy (org→folder→project), Org Policies |
| Multi-account/-project | AWS Organizations, SCPs | Management Groups, Azure Policy, Lighthouse | Resource hierarchy, Org Policies, VPC Service Controls |
| Just-in-time | AWS SSO + session policies, IAM Access Analyzer | Entra ID PIM, Privileged Identity Management | IAM recommender, Policy Troubleshooter |

## 🔴 Red Team view

### Long-lived access key exposure (contained)

**Scenario:** A developer accidentally commits an AWS access key to a public repo.

```bash
# Attacker discovers key in GitHub search (placeholder key):
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

aws sts get-caller-identity
# Output: { "Arn": "arn:aws:iam::111111111111:user/dev-ci-bot" }
```

**What the key unlocks (contained chain):**
```bash
# Discovery — what does this user have?
aws iam list-attached-user-policies --user-name dev-ci-bot
aws iam list-user-policies --user-name dev-ci-bot
aws iam list-groups-for-user --user-name dev-ci-bot

# If the user has sts:AssumeRole, enumerate roles:
aws iam list-roles | jq '.Roles[].Arn'

# Assume a privileged role:
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/admin-stage \
  --role-session-name ci-debug

# Now operating as admin-stage role — see [kill-chain-attack-mapping.md](./kill-chain-attack-mapping.md) for full chain.
```

**Artifacts:**
- CloudTrail: `GetCallerIdentity` from an unexpected IP address.
- CloudTrail: `AssumeRole` by the compromised user (source identity = `dev-ci-bot`).
- GuardDuty: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (if key used outside AWS).
- GuardDuty: `Recon:IAMUser/MaliciousIPCaller.Custom` (if from known-malicious IP).

**Equivalent Azure (contained):**
```bash
# Leaked service principal client secret:
az login --service-principal \
  --username 00000000-0000-0000-0000-000000000000 \
  --password 'placeholder-secret' \
  --tenant example.com
az account show
```

**Equivalent GCP (contained):**
```bash
# Leaked service account key file:
gcloud auth activate-service-account sa-example@project-id.iam.gserviceaccount.com \
  --key-file=leaked-key.json
gcloud auth list
gcloud projects list
```

## 🔵 Blue Team view

### Detection of anomalous assume-role

```sql
-- AWS CloudTrail: AssumeRole from a user/role that rarely assumes roles
SELECT eventTime, userIdentity.arn AS sourceIdentity,
       requestParameters.roleArn AS targetRole,
       requestParameters.roleSessionName,
       sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.arn NOT IN (
    SELECT userIdentity.arn FROM cloudtrail_logs
    WHERE eventName = 'AssumeRole'
    GROUP BY userIdentity.arn
    HAVING count(*) > 50  -- "rarely assumes"
  )
  AND date(eventTime) >= current_date - interval '1' day
```

```kusto
// Azure: Service principal sign-in from new IP
SigninLogs
| where AppId == "00000000-0000-0000-0000-000000000000"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by IPAddress, AppId
| where FirstSeen > ago(1h)
```

### Preventive guardrails

| Guardrail | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| No long-lived access keys | IAM policy deny `iam:CreateAccessKey` for human users; enforce SSO | Conditional Access: block legacy auth; require MFA | Org Policy `iam.disableServiceAccountKeyCreation` |
| Token-only service identity | IAM roles + IRSA (IRSA = IAM Roles for Service Accounts on EKS) | Managed Identity only — no client secrets | Workload Identity Federation — no service-account keys |
| Just-in-time privilege | IAM Access Analyzer + custom session duration limits | Entra ID Privileged Identity Management (PIM) | IAM Conditions + short-lived SA tokens |
| Permission boundaries | SCPs at org level; permission boundaries on roles | Management groups + Azure Policy deny effects | Org Policies + VPC Service Controls |
| External-id on cross-account roles | `sts:ExternalId` condition on trust policy | Cross-tenant trust with specific AppId | Workload Identity Federation with attribute mapping |

### Response steps for leaked credential

1. **Immediate:** Delete the access key (`aws iam delete-access-key`), rotate all other keys for the identity, revoke active sessions (`aws iam list-roles` → `RevokeSession`).
2. **Scope:** Query CloudTrail for all actions performed by the compromised identity in the last 7 days. Determine data accessed.
3. **Contain:** Apply an SCP to deny the compromised identity from further action. Create a forensic snapshot of resources accessed.
4. **Remediate:** Create a new identity with least-privilege permissions. Transition to SSO/token-based auth.
5. **Post-mortem:** Update the responsibility inventory ([shared-responsibility.md](./shared-responsibility.md)) to note the gap.

## Hands-on lab

1. **In AWS:** Create an IAM user `lab-user` with console access. Attach `AdministratorAccess`.
   - Run `aws sts get-caller-identity --profile lab-user` to verify.
   - Replace with a least-privilege policy: only `s3:GetObject` on a specific bucket.
   - Create an IAM role with the new policy. Demonstrate `sts:AssumeRole` from `lab-user`.
2. **In Azure:** Create a service principal. Grant `Reader` on a resource group.
   - Run `az role assignment list --assignee <sp-object-id>`.
   - Use Managed Identity on a test VM instead of client secret.
3. **In GCP:** Create a service account. Grant `roles/storage.objectViewer`.
   - `gcloud auth activate-service-account` with a key file.
   - Then disable the key and switch to Workload Identity Federation simulation.
4. **Audit:** For each cloud, query `who can call GetCallerIdentity`-equivalent:
   ```bash
   # AWS
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111111111111:role/ReadOnlyRole \
     --action-names sts:GetCallerIdentity
   # Azure
   az role assignment list --include-inherited --assignee <principal>
   # GCP
   gcloud iam roles describe roles/iam.serviceAccountTokenCreator
   ```

**Teardown:** Delete IAM users/roles/service accounts created.

## Detection rules & checklists

- [ ] No human IAM user has an access key. All humans use SSO.
- [ ] All service identities use roles / managed identities / Workload Identity — no static keys.
- [ ] CloudTrail / Activity Log / Cloud Audit Logs enabled in all regions/accounts/projects.
- [ ] GuardDuty / Defender for Cloud / Event Threat Detection enabled.
- [ ] `AssumeRole` events reviewed weekly for anomalous chains.
- [ ] External-id enforced on all cross-account/cross-project trust relationships.
- [ ] Permission boundaries implemented on all human-created roles.
- [ ] Break-glass account exists with MFA, firewalled to specific IPs, and alerting.

## References
- AWS IAM documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html
- Azure Entra ID overview: https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/
- GCP IAM overview: https://cloud.google.com/iam/docs/overview
- NIST SP 800-63 (Digital Identity Guidelines)
