# 09 — Entity Behaviour & UEBA Basics

> **Level:** Advanced
> **Prereqs:** [Native Threat Detection Guardduty Defender Scc](native-threat-detection-guardduty-defender-scc.md) (Native Threat Detection), [Detection As Code Sigma & Custodian](detection-as-code-sigma-and-custodian.md) (Detection as Code)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Discovery, Lateral Movement, Defense Evasion
> **Authorization scope:** Enable UEBA features only in your own sandbox. Behavioral models should be trained on your own account activity. All findings shown are from your own intentional test activity.

## What & why

UEBA (User and Entity Behavior Analytics) adds per-entity baselines on top of signature rules. Instead of "did someone call `CreateAccessKey`?," UEBA asks "does this principal *normally* call `CreateAccessKey` at 3 AM from a Russian IP?" Each cloud's native threat detection now ships ML-based UEBA modules: GuardDuty behavioral detectors, Sentinel UEBA, and (emerging) SCC Premium anomaly behaviors.

## The OnPrem reality

Splunk's `streamstats` with standard deviation (`stdev`) over authentication events was the homemade UEBA. You wrote SPL to compute a user's average login count per hour over 30 days, then alert when the current hour's count exceeded `avg + 3*stdev`. It worked but broke every time a new hire joined, a PTO pattern changed, or the baseline drifted due to seasonality.

## Cross-cloud UEBA comparison

| Capability | AWS GuardDuty | Azure Sentinel UEBA | GCP SCC Premium | OnPrem (Splunk ELK) |
|---|---|---|---|---|
| Per-entity baseline | Per IAM principal + IP: `AnomalousBehavior` | Per user/device: entity behaviour analytics, AD anomalies | Per principal/service-account: `iam:AnomalousGrant`, `iam:UnusualAccess` (as of June 2026, active SCC finding types) | Custom `streamstats` over auth logs |
| New geography detection | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | `Impossible travel activity` | (as of June 2026, SCC does not have a direct "impossible travel" finding; use SCC Event Threat Detection `iam:UnusualAccess` or enrich with third-party geo-IP) | GeoIP enrichment on source IP |
| Credential exfiltration | `CredentialExfiltration:IAMUser/AnomalousBehavior` | `Suspicious credential usage` | `iam:AnomalousServiceAccount` (as of June 2026, active SCC finding type) | Custom query on key creation + usage gap |
| Abnormal API call volume | CloudTrail Insights (separate paid feature) | `Anomalies: login attempts` | SCC Event Threat Detection | `streamstats` over event count/hour |
| Data exfiltration (DLP-ish) | `Exfiltration:S3/AnomalousBehavior` | Sentinel UEBA data exfil patterns | `storage:BucketIsPublic` (not UEBA per se; as of June 2026, SCC Event Threat Detection covers data exfiltration via `Exfiltration:*` finding types) | S3 access log analysis over time window |
| UEBA model retraining cadence | Automatic, continuous | Automatically updated every 7 days | (as of June 2026, SCC Premium model retraining cadence is continuous; verify current interval in SCC documentation) | Manual |

### GuardDuty behavioral finding types

| Finding type | What triggers it | Example |
|---|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | IAM User's STS credentials used from outside its typical VPC | DevUser's creds appear on a DigitalOcean IP |
| `CredentialExfiltration:IAMUser/AnomalousBehavior` | IAM user creates or uses access keys from an unusual location | AKIA key used from China, user usually US-based |
| `Exfiltration:S3/AnomalousBehavior` | Unusually high S3 GET volume from a principal | Single EC2 role downloads 50,000 objects in 10 minutes |
| `Discovery:S3/TorIPCaller` | S3 API call from a Tor exit node | `ListBuckets` from Tor exit node |
| `DefenseEvasion:IAMUser/CloudTrailLoggingDisabled` | StopLogging or DeleteTrail called by non-admin | Dev user disables trail in dev account |

## AWS — GuardDuty behavioral detection samples

### Enable GuardDuty (UEBA is built-in, no separate flags)

```bash
aws guardduty create-detector --enable
# GuardDuty behavioral models train automatically on your account's activity.
# No action needed beyond enabling the detector.
```

### Sample finding: `CredentialExfiltration:IAMUser/AnomalousBehavior`

```json
{
  "accountId": "111111111111",
  "type": "CredentialExfiltration:IAMUser/AnomalousBehavior",
  "severity": 7.5,
  "resource": {
    "accessKeyDetails": {
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "principalId": "AIDAJ6ODN7EXAMPLE",
      "userName": "eng-dev-01",
      "userType": "IAMUser"
    }
  },
  "service": {
    "action": {
      "actionType": "AWS_API_CALL",
      "awsApiCallAction": {
        "api": "sts:GetCallerIdentity",
        "serviceName": "sts.amazonaws.com",
        "callerType": "Remote IP",
        "remoteIpDetails": {
          "ipAddressV4": "198.51.100.42",
          "organization": {"asn": "12345", "asnOrg": "ExampleVPS", "isp": "ExampleVPS"},
          "country": {"countryName": "Russia"},
          "city": {"cityName": "Moscow"}
        }
      }
    },
    "anomalyDetected": true,
    "anomalyDetails": {
      "modelVersion": "v2",
      "anomalyReason": "IAM user accessed from a geo-location and ASN they have never used before"
    }
  }
}
```

### Query GuardDuty behavioral findings

```bash
aws guardduty list-findings \
  --detector-id <id> \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CredentialExfiltration:IAMUser/AnomalousBehavior"]}}}'

# Then get full details:
aws guardduty get-findings --detector-id <id> --finding-ids <finding-id>
```

## Azure — Sentinel UEBA

### Enable UEBA in Sentinel

Sentinel UEBA is enabled at the Sentinel workspace level:

```bash
az sentinel entity-behavior-analytics create \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace \
  --name default
```

> (as of June 2026, Sentinel UEBA is enabled via the Azure portal under Sentinel → Entity behavior analytics → Settings, or via ARM template. Check the [Sentinel UEBA docs](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) for current CLI/API enablement paths.)

### UEBA data sources

Sentinel UEBA builds entity profiles from:
- Entra ID Sign-in / Audit logs
- Microsoft 365 audit logs (if connected)
- Azure Activity Log
- SecurityEvent (Windows Event Log from connected VMs)
- Microsoft Defender for Endpoint alerts

### Sample Sentinel UEBA enrichment

When an incident is created, UEBA enriches the entities view:

| User | Investigation Priority | Insights |
|---|---|---|
| `dev-user@example.com` | High | This user's account signed in from a new ASN. Account not seen in this geography in 30 days. Password change occurred 5 minutes before anomalous sign-in. |

### KQL to query UEBA analytics

```kql
BehaviorAnalytics
| where ActivityType == "FailedLogOn"
| summarize Count=count() by UserPrincipalName, SourceIPAddress, DestinationIPAddress
| where Count > 50
| order by Count desc

// Entity info — show the UEBA profile for a specific user
IdentityInfo
| where AccountUPN == "dev-user@example.com"
| project AccountUPN, AssignedRoles, City, Country, Department, IsAccountEnabled
```

## GCP — SCC Event Threat Detection (UEBA module)

> (as of June 2026, SCC Event Threat Detection UEBA-related finding types include `iam:AnomalousGrant`, `iam:UnusualAccess`, `iam:AnomalousServiceAccount`, and `exfiltration:*` finding types. Reference [SCC finding types](https://cloud.google.com/security-command-center/docs/finding-types) for the current complete list.)

### Enable SCC Premium

```bash
gcloud services enable securitycenter.googleapis.com
gcloud scc services enable \
  --organization organizations/111111111111 \
  --service EVENT_THREAT_DETECTION
```

### List UEBA-related findings

```bash
gcloud scc findings list organizations/111111111111 \
  --filter "findingClass=\"THREAT\" AND severity=\"HIGH\"" \
  --format "table(finding.name, finding.category, finding.resourceName, finding.createTime)"
```

### Sample finding query (BigQuery)

```sql
SELECT
  finding.category,
  finding.resourceName,
  finding.severity,
  finding.createTime,
  finding.sourceProperties.anomaly_reason
FROM `project-id-111111.audit_logs.scc_findings`
WHERE finding.category LIKE '%Anomalous%'
  AND finding.createTime > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
ORDER BY finding.createTime DESC;
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Baseline engine | Splunk `streamstats` + `stdev` | GuardDuty behavioral ML | Sentinel UEBA engine | SCC Event Threat Detection |
| Entity definition | AD user / machine account | IAM principal + IP + userAgent | Entra ID user + device ID | Service account + IAM principal |
| Anomaly signals | Failed login volume, new process, data volume | Geo-anomaly, API call cadence, ASN change | Impossible travel, credential usage timing, new device | IAM binding changes, unusual data access pattern, ASN change |
| Baseline retrain | Manual (Splunk lookup refresh) | Continuous (GuardDuty) | 7-day auto refresh | (as of June 2026, SCC Premium retrains continuously; verify current interval in SCC documentation) |
| Finding output | Custom Splunk alert → email | GuardDuty finding → EventBridge | Sentinel incident → Playbook | SCC finding → Pub/Sub |
| False positive tuning | Manual threshold adjustment | Trusted IP list, suppression rules | Sentinel tuning analytics rules | SCC mute rules |

## 🔴 Red Team view

### Living-off-the-land: spacing high-signal calls within normal cadence

UEBA models detect statistical outliers. An attacker who understands the model's temporal granularity can interleave malicious API calls with benign ones, keeping anomaly scores below threshold.

**Narrative:**

The attacker has compromised a dev IAM role that normally calls `sts:AssumeRole` ~15 times/day from 9 AM–6 PM Pacific. The attacker wants to assume the `ProdReadOnly` role and exfiltrate S3 data.

Instead of assuming the role immediately from a Russian IP at 3 AM (instant GuardDuty behavioral alert), the attacker:

1. Waits until business hours Pacific (10 AM).
2. Uses a VPN to an AWS us-west-2 EC2 instance (same region as normal activity, same ASN as AWS).
3. Intersperses `AssumeRole` to `ProdReadOnly` with normal `AssumeRole` calls to `DevReadOnly`.
4. Spreads the S3 `GetObject` calls across 8 hours, never exceeding 1,000 requests/hour (within 1.5x of normal S3 read volume for this role).

```bash
# Attacker simulation (contained, run in your own sandbox):
# Step 1: Normal cadence — 10 AssumeRole calls to DevReadOnly per hour
for hour in $(seq 9 17); do
  for i in $(seq 1 10); do
    aws sts assume-role --role-arn arn:aws:iam::111111111111:role/DevReadOnly --role-session-name "normal-session-${i}"
  done
  # Step 2: Interleave 1 malicious AssumeRole per hour
  aws sts assume-role --role-arn arn:aws:iam::111111111111:role/ProdReadOnly --role-session-name "normal-looking"
  # Step 3: Slow data exfiltration — 50 GetObject calls spread across the hour
  for j in $(seq 1 50); do
    aws s3 cp s3://prod-data-111111111111/backup-$(date +%Y%m%d).enc /dev/null &
    sleep 72  # 50 calls in ~1 hour
  done
  sleep 3600
done
```

**What may still trigger:**
- GuardDuty `Exfiltration:S3/AnomalousBehavior` — if 50 GetObject/hour × 8 hours exceeds the role's S3 read baseline (even if per-hour spikes look normal).
- If `ProdReadOnly` AssumeRole is never used by this role, the *first* call is an anomaly.
- Any data event on S3 that exceeds a bucket-level baseline may still flag.

**What this evades:**
- Single geo-anomaly (`CredentialExfiltration`) — because VPN is in the same region.
- Time-of-day anomaly — because calls happen during business hours.
- Volume spike signature rules — because calls stay within 1.5x normal.

**Defensive pairing:** UEBA with per-*role-combination* profiles (not just per-principal) — the pair `DevRole → ProdReadOnly` has never been seen before, and that adjacency should flag. Over longer windows (30-day baselines), a role that *never* called `AssumeRole` on `ProdReadOnly` creates a zero-to-one anomaly, which is the strongest UEBA signal.

### Artifacts

- CloudTrail logs every `AssumeRole` and `GetObject` — they just look like normal activity.
- The `userAgent` and `sourceIPAddress` remain consistent.
- The only anomaly is *role adjacency* (`DevReadOnly → ProdReadOnly`) plus a slight volume increase in S3 reads.

## 🔵 Blue Team view

### Tuning UEBA thresholds

**GuardDuty suppression rules:**
```bash
aws guardduty create-filter \
  --detector-id <id> \
  --name "suppress-deployment-pipeline" \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"]}}}' \
  --action ARCHIVE \
  --description "CI/CD pipeline uses STS cross-region — expected"
```

**Sentinel UEBA tuning:** In the Sentinel portal → Analytics → Anomalies → adjust sensitivity per rule.

### Entity profiles — the "new ASN for entity X" signal

Build a lookup table of known-good ASNs per entity:

```sql
-- BigQuery: per-service-account known ASNs
CREATE TABLE `project-id-111111.sec_profile.known_asns` AS
SELECT
  protoPayload.authenticationInfo.principalEmail AS principal,
  protoPayload.requestMetadata.callerIp AS ip,
  COUNT(*) AS count
FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
GROUP BY principal, ip
HAVING count > 100;
```

Then alert on new ASNs:

```sql
WITH current AS (
  SELECT DISTINCT
    protoPayload.authenticationInfo.principalEmail AS principal,
    protoPayload.requestMetadata.callerIp AS ip
  FROM `project-id-111111.audit_logs.cloudaudit_googleapis_com_activity`
  WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
)
SELECT c.principal, c.ip
FROM current c
LEFT JOIN `project-id-111111.sec_profile.known_asns` k
  ON c.principal = k.principal AND c.ip = k.ip
WHERE k.principal IS NULL;
```

### Compound detection: rule + UEBA

| Sigma rule (deterministic) | UEBA signal (probabilistic) | Combined alert |
|---|---|---|
| `AttachRolePolicy` on `AdministratorAccess` | AND caller IP ASN never seen for this principal in 90 days | Critical — likely compromise |
| `CreateAccessKey` | AND principal's typical key-creation rate is 0 over 90 days | High — possible credential exfil |
| `DeleteTrail` | AND call timestamp outside principal's normal working hours | High — probable defense evasion |
| `PutBucketPolicy` with `*` principal | AND bucket never had public policy before | Medium — misconfig or test |

### Response to UEBA findings

1. **Investigate the entity profile:** what's the principal's normal IP range, API call volume, and role adjacencies?
2. **Pivot to rule-based detections:** did any deterministic Sigma rule also fire for this principal in the same window?
3. **Check for model pollution:** was this entity's baseline trained on attacker activity? If the attacker had persistence for 30+ days, the model considers malicious activity "normal."
4. **Quarantine:** attach a temporary deny policy, rotate credentials, initiate Tier 2 investigation.

## Hands-on lab

1. Enable GuardDuty in your sandbox (if not already enabled):
```bash
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

2. Generate a behavioral anomaly by calling `sts:GetCallerIdentity` from a VPN IP (simulating geo-anomaly):
```bash
# If you have a VPN, connect to a non-US endpoint, then:
aws sts get-caller-identity
# GuardDuty may generate a credential exfiltration finding within hours.
```

3. Check for findings after 1–6 hours:
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query DetectorIds[0] --output text)
aws guardduty list-findings --detector-id $DETECTOR_ID
aws guardduty get-findings --detector-id $DETECTOR_ID --finding-ids <id>
```

4. Create a suppression rule for your known-good VPN IP:
```bash
aws guardduty create-filter \
  --detector-id $DETECTOR_ID \
  --name "my-known-vpn" \
  --finding-criteria '{"Criterion":{"service.action.awsApiCallAction.remoteIpDetails.ipAddressV4":{"Eq":["YOUR.VPN.IP.ADDRESS"]}}}' \
  --action ARCHIVE
```

5. **Teardown:**
```bash
aws guardduty delete-filter --detector-id $DETECTOR_ID --filter-name my-known-vpn
aws guardduty delete-detector --detector-id $DETECTOR_ID
```

## Detection rules & checklists

```
# Checklist
- [ ] GuardDuty / Sentinel UEBA / SCC Premium enabled
- [ ] Suppression rules created for known-good anomalies (deployment pipelines, VPNs)
- [ ] Per-entity ASN profiles queried monthly; anomalies flagged
- [ ] Rule + UEBA compound alerts configured for top-5 critical detections
- [ ] Baseline retraining interval verified (automatic for GuardDuty, 7-day for Sentinel)
- [ ] UEBA model not accidentally trained on polluted data (check for 30-day attacker dwell)
- [ ] Monthly review: which UEBA findings were false positives? Tune or suppress.
```

## References
- [GuardDuty behavioral findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Sentinel UEBA documentation](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics)
- [SCC Event Threat Detection](https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview)
- [GCP SCC finding types reference](https://cloud.google.com/security-command-center/docs/finding-types)
- [../IAM/assume-role-chains-and-trust-graphs.md](../IAM/assume-role-chains-and-trust-graphs.md)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
