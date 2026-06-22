# 01 — Capstone Architecture Overview

> **Level:** Advanced
> **Prereqs:** Modules 00–12
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact
**Authorization scope:** Capstone labs are to be run only against learner-owned sandbox accounts. Placeholder accounts are used throughout. No live attack surfaces.

## What & why

The capstone scenario is a single deliberately-vulnerable reference organisation deployed across AWS, Azure, and GCP. Both the red-team killchain (Module 09) and the blue-team detection/response (Modules 06/10/11) operate on identical infrastructure. One architecture, two opposing narratives, one timeline.

## The OnPrem reality

A traditional enterprise lab would deploy: one domain controller with weakened password policy, one IIS web tier with unpatched SSRF, one SQL Server with default `sa` credentials, and a file share with `Everyone:FullControl`. The cloud capstone translates every one of those weaknesses into managed-service equivalents.

## Core concepts

### Shared architecture primitives

```
┌─────────────────────────────────────────────────────────────┐
│                    IdP / SSO (placeholder)                    │
│      AWS SSO / Azure AD / GCP Cloud Identity                 │
└──────────────┬──────────┬──────────┬────────────────────────┘
               │          │          │
      ┌────────▼───┐ ┌───▼────────┐ ┌──▼──────────────┐
      │ Production │ │  Staging   │ │  SharedServices  │
      │ Account    │ │  Account   │ │  Account         │
      │111111111111│ │222222222222│ │333333333333      │
      └──────┬─────┘ └──┬─────────┘ └──┬───────────────┘
             │           │              │
    ┌────────▼───────────▼──────────────▼─────────────────────┐
    │              Cross-Account AssumeRole Trusts              │
    │  Prod → SharedServices (AdministratorAccess)             │
    │  Staging → SharedServices (ReadOnly + S3)                │
    │  SharedServices has trust back to Prod (PowerUser)       │
    └─────────────────────────────────────────────────────────┘
```

| Component | Deliberate weakness | Exploited in stage | Blue control module |
|---|---|---|---|
| 3-tier web app (LB→serverless/container→DB+object store) | SSRF endpoint in web tier | Initial Access ([09-03](../Red-Team-Offense/initial-access-vectors.md)) | [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) |
| Object store bucket | BlockPublicAccess OFF, ACL `public-read` on one prefix | Recon ([09-02](../Red-Team-Offense/recon-osint-and-fingerprint.md)), Collection ([09-09](../Red-Team-Offense/collection-data-exfil-channels.md)) | [04-02](../Storage-Data-Security/public-exposure-and-block-public.md), [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) |
| CI runner IAM role / SP / SA | `AdministratorAccess` equivalent, long-lived key in env | Initial Access ([09-03](../Red-Team-Offense/initial-access-vectors.md)) | [08-06](../IaC-Security/cicd-runner-as-cloud-principal.md), [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) |
| Cross-account trust chain | `sts:AssumeRole` with `*` principal in trust policy | Privilege Escalation ([09-05](../Red-Team-Offense/privilege-escalation-catalogue.md)), Lateral Movement ([09-06](../Red-Team-Offense/lateral-movement-and-pivoting.md)) | [02-03](../IAM/assume-role-chains-and-trust-graphs.md), [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md) |
| Lambda / Function / Cloud Function | `iam:PassRole` to admin role, no resource constraint | Privilege Escalation ([09-05](../Red-Team-Offense/privilege-escalation-catalogue.md)) | [06-05](../Monitoring-Detection-SIEM/native-threat-detection-guardduty-defender-scc.md) |
| IAM user with console access | No MFA, long-lived access key | Persistence ([09-07](../Red-Team-Offense/persistence-techniques-in-cloud.md)) | [10-04](../Blue-Team-Defense/deception-honeytokens.md) |
| Object-Locked bucket | Attacker attempts `DeleteObject` → denied | Impact ([09-09](../Red-Team-Offense/collection-data-exfil-channels.md)) | [04-04](../Storage-Data-Security/object-lock-and-worm.md) |

### Killchain summary (both variants)

| # | Stage | Red action (synthesis of Module 09) | Blue control (synthesis of Modules 06/10/11) |
|---|---|---|---|
| 1 | Recon | Passive enumeration of public objects, tenant discovery | List/Get ratio monitoring, honey-token S3 object hit alert |
| 2 | Initial Access | SSRF→IMDS credential theft + CI runner key leak | CloudTrail `GetCallerIdentity` from unknown IP, gitleaks CI action |
| 3 | Privilege Escalation | `iam:PassRole` to `lambda:CreateFunction`, Azure RBAC elevation, GCP `iam.serviceAccountTokenCreator` | GuardDuty `PrivilegeEscalation`, Defender `ElevatedAccess`, SCC finding |
| 4 | Persistence | `iam:CreateAccessKey` on another IAM user, Lambda event-source mapping | Honey-token key touch, daily `CreateAccessKey` diff alert |
| 5 | Lateral Movement | Assume-role chain through 3 accounts | Cross-cloud `AssumeRole` untyped trust alert, trust-graph comparison |
| 6 | Collection | `s3:ListObjects` → `s3:GetObject` storm, bucket contents staged | List/Get ratio anomaly, SIEM alert on data volume spike |
| 7 | Impact | `s3:DeleteObject` on Object-Locked bucket → `AccessDenied` | CloudTrail denied event, WORM evidence preserved |

## AWS — topology

```
                        Internet
                           │
                    ┌──────▼──────┐
                    │   ALB/NLB   │
                    │  (public)   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼──┐  ┌─────▼──────┐  ┌──▼───────────┐
     │ Lambda fn │  │ ECS Fargate│  │  EC2 (IMDSv1)│
     │ (app)     │  │ (worker)   │  │  (SSRF vuln) │
     │           │  │            │  │              │
     │ PassRole→ │  │            │  │ SSRF→169.254 │
     │ admin     │  │            │  │ role creds   │
     └─────┬─────┘  └─────┬──────┘  └──────┬────────┘
           │              │                │
           └──────────────┼────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
     ┌────────▼──────┐     ┌──────────▼──────────┐
     │  RDS MySQL    │     │  S3 bucket           │
     │  (encrypted)  │     │  BlockPublicAccess:  │
     │               │     │    OFF               │
     │               │     │  ObjectLock: enabled │
     └───────────────┘     │    on one prefix     │
                           └─────────────────────┘

         IAM Roles / Users:
         ┌────────────────────────────────────────┐
         │ ci-deployer (IAM user)                  │
         │   Key: AKIAIOSFODNN7EXAMPLE             │
         │   Policy: AdministratorAccess           │
         │   ─ leaked in public GitHub repo        │
         ├────────────────────────────────────────┤
         │ ProdLambdaExecRole                      │
         │   Trust: lambda.amazonaws.com           │
         │   Policy: AdministratorAccess           │
         │   ─ PassRole target for escalation      │
         ├────────────────────────────────────────┤
         │ CrossAccountRole (SharedServices)       │
         │   Trust: arn:aws:iam::111111111111:root │
         │   Policy: PowerUserAccess               │
         │   ─ overly broad trust                  │
         └────────────────────────────────────────┘
```

## Azure — topology

```
                        Internet
                           │
                    ┌──────▼──────┐
                    │ Application │
                    │  Gateway    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼──┐  ┌─────▼──────┐  ┌──▼──────────────┐
     │ Function  │  │ ACI /      │  │  VMSS           │
     │ App       │  │ Container  │  │  (IMDS)         │
     │           │  │ Apps       │  │                 │
     │ Managed   │  │            │  │ SSRF→169.254.   │
     │ Identity  │  │            │  │ 169.254/token   │
     └─────┬─────┘  └─────┬──────┘  └──────┬──────────┘
           │              │                │
           └──────────────┼────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
     ┌────────▼──────┐     ┌──────────▼───────────┐
     │  Azure SQL DB │     │  Storage Account      │
     │               │     │  blob container       │
     │               │     │  public access: blob  │
     │               │     │  immutability: locked │
     └───────────────┘     └──────────────────────┘

         Service Principals:
         ┌────────────────────────────────────────┐
         │ ci-deployer-sp (App Registration)       │
         │   Secret: ~z8Q~example...               │
         │   Role: Owner on subscription           │
         │   ─ leaked in public repo               │
         ├────────────────────────────────────────┤
         │ prod-func-identity (Managed Identity)   │
         │   Role: Contributor on subscription     │
         │   ─ fetched via SSRF→IMDS               │
         ├────────────────────────────────────────┤
         │ cross-sub-reader (SP in tenant)         │
         │   Assigned: Reader on target sub        │
         │   ─ no conditional access              │
         └────────────────────────────────────────┘
```

## GCP — topology

```
                        Internet
                           │
                    ┌──────▼──────┐
                    │  Cloud Load │
                    │  Balancer   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼──┐  ┌─────▼──────┐  ┌──▼───────────────┐
     │ Cloud     │  │ Cloud Run  │  │  GCE (IMDSv1)    │
     │ Function  │  │ (worker)   │  │                  │
     │           │  │            │  │ SSRF→169.254.    │
     │ SA with   │  │            │  │ 169.254/token    │
     │ iam.token │  │            │  │                  │
     │ Creator   │  │            │  │                  │
     └─────┬─────┘  └─────┬──────┘  └──────┬───────────┘
           │              │                │
           └──────────────┼────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
     ┌────────▼──────┐     ┌──────────▼──────────┐
     │  Cloud SQL    │     │  GCS bucket          │
     │  PostgreSQL   │     │  publicAccess: true  │
     │               │     │  retention policy:   │
     │               │     │    locked (1 prefix) │
     └───────────────┘     └─────────────────────┘

         Service Accounts:
         ┌────────────────────────────────────────┐
         │ ci-deployer@example-project.iam.gsa... │
         │   Key: JSON file leaked in public repo  │
         │   Role: roles/owner on project          │
         ├────────────────────────────────────────┤
         │ prod-func-sa@example-project.iam.gsa... │
         │   Role: roles/editor                    │
         │   iam.serviceAccountTokenCreator: true  │
         │   ─ fetched via SSRF→IMDS               │
         ├────────────────────────────────────────┤
         │ cross-project-reader@shared.iam.gsa...  │
         │   IAM: roles/viewer on target project   │
         │   ─ no VPC SC, no org policy restriction│
         └────────────────────────────────────────┘
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Web tier SSRF vuln | IIS/PHP `file_get_contents($_GET['url'])` | EC2 + IMDSv1 + Lambda proxy → `169.254.169.254` | VMSS + IMDS → `169.254.169.254/metadata/identity/oauth2/token` | GCE + IMDSv1 → `169.254.169.254/computeMetadata/v1/...` |
| Leaked CI creds | Jenkins `credentials.xml` on public share | IAM access key `AKIAIOSFODNN7EXAMPLE` in `.env` | SP secret `~z8Q~` in repo | SA key JSON in `secrets/` |
| Overly broad trust | `Domain Admins` in every local `Administrators` | `"Principal": {"AWS": "*"}` in trust policy | RBAC `Owner` assigned cross-subscription without conditions | `roles/owner` granted to external SA |
| Public data | `Everyone:Read` on `\\fileserver\share` | `s3:GetObject` with `Principal: "*"` | Blob container anonymous read access | `allUsers` granted `storage.objectViewer` |
| WORM protection | SnapLock on NetApp, legal hold on backup tapes | S3 Object Lock governance mode | Blob immutability policy (locked) | GCS retention policy (locked) |

## 🔴 Red Team view

The red variant begins from two foothold primitives — both deliberately placed:

1. **External SSRF endpoint** in the web application tier (`curl "http://app.example.com/fetch?url=http://169.254.169.254/..."` — see [09-03](../Red-Team-Offense/initial-access-vectors.md)).
2. **Leaked CI runner credentials** placed in a simulated public repository (see [09-03](../Red-Team-Offense/initial-access-vectors.md) and [08-06](../IaC-Security/cicd-runner-as-cloud-principal.md)).

From either entry, the red team follows the killchain defined in [09-11](../Red-Team-Offense/building-a-simple-apt.md): recon → initial access → privilege escalation → persistence → lateral movement → collection → (attempted) impact. Every action is logged; no evasion techniques are applied (the capstone values observability over stealth — see [09-08](../Red-Team-Offense/evasion-and-trail-free-actions.md) for what *could* be done).

The red variant *intentionally* leaves CloudTrail/Activity Log/Cloud Audit Log entries at every stage so the blue variant can detect them.

## 🔵 Blue Team view

The blue variant operates assuming the attacker has achieved their first foothold. Day 0 (pre-deployment) hardening from [10-02](../Blue-Team-Defense/preventive-guardrails-as-code.md) is applied:

- SCPs / Azure Policy deny assignments / GCP Org Policy that prevent `s3:PutBucketPublicAccessBlock` with `false`
- IAM boundary quarantine policies from [02-06](../IAM/permission-boundaries-and-quarantine.md)
- Block-public-access enforcement from [04-02](../Storage-Data-Security/public-exposure-and-block-public.md)

Day 7 detection ingests all control-plane logs via [06-02](../Monitoring-Detection-SIEM/cloudtrail-activity-and-data-events.md), [06-03](../Monitoring-Detection-SIEM/azure-log-analytics-and-sentinel.md), [06-04](../Monitoring-Detection-SIEM/gcp-cloud-audit-logs-and-scc.md) and applies the detection pack in [`detections/capstone-detection-pack.md`](./detections/capstone-detection-pack.md). Honey-tokens from [10-04](../Blue-Team-Defense/deception-honeytokens.md) are deployed: an inactive IAM access key on a dummy user, a canary S3 object, and a decoy role trust relationship.

The IR runbook from [11-01](../IR-Forensics-Cloud/ir-runbook-cloud-aware.md) is exercised: snapshot, revoke, quarantine, preserve, eradicate.

## References

- [Module 09 — Red Team Offense](../Red-Team-Offense/README.md)
- [Module 10 — Blue Team Defense](../Blue-Team-Defense/README.md)
- [Module 11 — IR & Forensics](../IR-Forensics-Cloud/README.md)
- [Module 06 — Monitoring & Detection](../Monitoring-Detection-SIEM/README.md)
- MITRE ATT&CK Cloud Matrix — Initial Access, Privilege Escalation, Persistence, Lateral Movement, Collection, Exfiltration, Impact
