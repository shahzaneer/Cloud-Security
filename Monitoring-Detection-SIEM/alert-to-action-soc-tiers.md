# 08 — Alert to Action: SOC Tiers

> **Level:** Intermediate
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md), [Cloudtrail Activity & Data Events](cloudtrail-activity-and-data-events.md), [Azure Log Analytics & Sentinel](azure-log-analytics-and-sentinel.md), [GCP Cloud Audit Logs & Scc](gcp-cloud-audit-logs-and-scc.md), [Native Threat Detection Guardduty Defender Scc](native-threat-detection-guardduty-defender-scc.md), [Ingestion Pipeline SIEM Patterns](ingestion-pipeline-siem-patterns.md), [Detection As Code Sigma & Custodian](detection-as-code-sigma-and-custodian.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Impact (resource consumption via alert flood)
> **Authorization scope:** All automation examples use placeholder webhook URLs, Lambda ARNs, and subscription IDs. Deploy only in your own sandbox with deliberate benign trigger events.

## What & why

Detection alone is useless — an alert without a human or automated response is just a line in Kibana. The alert lifecycle runs Tier 1 (triage, < 15 min) → Tier 2 (investigation, < 1 hr) → Tier 3 (incident response, < 24 hr). Each cloud provides event routing services (EventBridge, Logic Apps, Cloud Functions), and piping alerts to Slack/PagerDuty closes the detection-to-action gap.

## The OnPrem reality

The SOC runbook lived in Confluence — "if Splunk alert X fires, copy-paste this SPL query, check this spreadsheet, then email the sysadmin." No auto-routing, no enrichment, no version-controlled runbook. Alert fatigue was a career hazard, not a metric.

## Core concepts

### The SOC tier model

| Tier | Role | SLA | Tooling | Cloud-specific example |
|---|---|---|---|---|
| Tier 1 | Triage: verify alert, basic context check | 15 min | SIEM dashboard, Slack bot | Acknowledge GuardDuty finding in Security Hub |
| Tier 2 | Investigation: deep-dive, timeline, blast radius | 60 min | CloudTrail Lake, BigQuery, KQL | Query all `AssumeRole` calls by the principal last 24h |
| Tier 3 | Incident response: containment, eradication, recovery | 24 hr | Runbooks, Lambda auto-remediation | Attach deny policy → rotate credentials → snapshot forensic evidence |

### Alert routing matrix per cloud

| Action | AWS | Azure | GCP | OnPrem |
|---|---|---|---|---|
| Event source | GuardDuty finding, CloudTrail event, CW alarm | Defender alert, Sentinel incident, Activity Log | SCC finding, Logging metric alert | Splunk alert, ElastAlert rule |
| Router | EventBridge | Logic Apps / Sentinel automation rules | Pub/Sub + Cloud Functions / Workflows | Custom webhook handler |
| Notification target | SNS → Slack / PagerDuty | Teams connector / PagerDuty | Pub/Sub → Cloud Function → Slack | SMTP / Slack incoming webhook |
| Auto-response | Lambda | Logic Apps / Sentinel Playbook | Cloud Function / Cloud Run | Ansible / custom script |
| Case management | Security Hub findings → Jira | Sentinel incident → ServiceNow | SCC finding → custom Cloud Function | Manual Confluence page |

### Runbook template (Markdown in git, rendered in SIEM)

```markdown
# Runbook: AWS CloudTrail StopLogging
- Rule ID: RB-06-02-001
- Severity: Critical
- Tier 1 actions (15 min):
  1. Verify in CloudTrail Event History: `eventName=StopLogging`
  2. Note the `userIdentity.arn` and `sourceIPAddress`
  3. Acknowledge the alert in PagerDuty
  4. Escalate to Tier 2 if the principal is not the known break-glass role
- Tier 2 actions (60 min):
  1. Query CloudTrail Lake for all events by this principal in the past 1h
  2. Check if any other trails were also stopped
  3. Identify if the principal is an IAM User with long-lived keys (credential report)
- Tier 3 actions (24 hr):
  1. Attach DenyAll inline policy to the principal
  2. Re-enable the trail: `aws cloudtrail start-logging --name <trail>`
  3. Rotate the principal's keys
  4. File Jira incident with timeline + IoCs
```

## AWS — EventBridge → Lambda → Slack

### Step 1: EventBridge rule catching GuardDuty findings

```bash
aws events put-rule \
  --name guardduty-high-severity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7]}]
    }
  }'

aws events put-targets \
  --rule guardduty-high-severity \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:111111111111:function:slack-alert-guardduty"
```

### Step 2: Lambda function posting to Slack

```python
import json
import urllib.request
import os

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

def handler(event, context):
    finding = event['detail']
    severity = finding.get('severity', 0)
    finding_type = finding.get('type', 'unknown')
    resource = finding.get('resource', {}).get('instanceDetails', {}).get('instanceId', 'unknown')
    account = finding['accountId']

    slack_message = {
        "text": f"*GuardDuty High Severity Finding*",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Type", "value": finding_type, "short": True},
                {"title": "Severity", "value": str(severity), "short": True},
                {"title": "Account", "value": account, "short": True},
                {"title": "Resource", "value": resource, "short": True},
                {"title": "Investigate", "value": f"https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id={finding.get('id','')}", "short": False}
            ]
        }]
    }

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=json.dumps(slack_message).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req)
    return {"statusCode": 200}
```

**Least privilege IAM role for Lambda:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:us-east-1:111111111111:*"
    }
  ]
}
```

**Gotcha:** The Slack webhook URL is a secret — store in AWS Secrets Manager, not env var in Lambda.

## Azure — Logic Apps (Sentinel Playbook)

### Sentinel automation rule → Logic App

Create via Azure portal or ARM:

```json
{
  "type": "Microsoft.Logic/workflows",
  "apiVersion": "2019-05-01",
  "properties": {
    "definition": {
      "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
      "triggers": {
        "When_a_response_to_an_Azure_Sentinel_alert_is_triggered": {
          "type": "Microsoft.Sentinel/incidents/triggers",
          "kind": "Alert"
        }
      },
      "actions": {
        "Send_Slack_Message": {
          "type": "Http",
          "inputs": {
            "method": "POST",
            "uri": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX",
            "body": {
              "text": "@{triggerBody()?['object']?['properties']?['title']}",
              "attachments": [
                {
                  "fields": [
                    {"title": "Severity", "value": "@{triggerBody()?['object']?['properties']?['severity']}"},
                    {"title": "Description", "value": "@{triggerBody()?['object']?['properties']?['description']}"}
                  ]
                }
              ]
            }
          }
        }
      }
    }
  }
}
```

**CLI deployment:**
```bash
az logic workflow create \
  --resource-group rg-sec-monitor \
  --name sentinel-alert-to-slack \
  --definition @playbook-definition.json \
  --location eastus
```

### Sentinel automation rule (attach playbook to incident creation)

```bash
az sentinel automation-rule create \
  --resource-group rg-sec-monitor \
  --workspace-name central-workspace \
  --automation-rule-name "HighSevToSlack" \
  --triggering-logic "TriggersOnIncidents" \
  --order 1 \
  --actions '[{
    "order": 1,
    "actionType": "RunPlaybook",
    "actionId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec-monitor/providers/Microsoft.Logic/workflows/sentinel-alert-to-slack"
  }]' \
  --conditions '[{"conditionProperty": "IncidentSeverity", "operator": "Contains", "values": ["High"]}]'
```

## GCP — Cloud Function triggered on SCC finding

```bash
gcloud functions deploy scc-to-slack \
  --runtime python310 \
  --trigger-topic scc-findings \
  --entry-point handle_scc_finding \
  --set-secrets SLACK_WEBHOOK=slack-webhook:latest
```

```python
import base64
import json
import os
from urllib import request

SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', '')

def handle_scc_finding(event, context):
    finding = json.loads(base64.b64decode(event['data']).decode('utf-8')).get('finding', {})
    severity = finding.get('severity', 'LOW')
    category = finding.get('category', 'unknown')
    resource = finding.get('resourceName', 'unknown')

    if severity not in ('HIGH', 'CRITICAL'):
        return 'OK'

    payload = {
        "text": f"*GCP SCC {severity} Finding*",
        "attachments": [{
            "color": "danger" if severity == "CRITICAL" else "warning",
            "fields": [
                {"title": "Category", "value": category},
                {"title": "Resource", "value": resource},
                {"title": "Severity", "value": severity}
            ]
        }]
    }
    req = request.Request(SLACK_WEBHOOK, data=json.dumps(payload).encode(),
                          headers={'Content-Type': 'application/json'})
    request.urlopen(req)
    return 'OK'
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Alert source | Splunk alert / ElastAlert | EventBridge rule | Sentinel analytics rule | Logging metric → Pub/Sub |
| Routing engine | Custom script poll Elastic API | EventBridge → SNS/Lambda | Logic Apps / Sentinel automation | Pub/Sub → Cloud Functions |
| Notification | SMTP / Slack webhook | SNS → Lambda → Slack | Teams connector / HTTP action | Cloud Function → Slack |
| Auto-remediation | Ansible playbook triggered by webhook | Lambda (e.g., revoke IAM key) | Logic Apps (e.g., disable user) | Cloud Function (e.g., remove IAM binding) |
| Case management | Jira REST API from custom script | Security Hub → Jira plugin | Sentinel → ServiceNow connector | Custom Cloud Function → Jira |
| Runbook storage | Confluence / git wiki | Markdown in repo + SSM documents | Azure Automation runbooks | Cloud Functions source in git |

## 🔴 Red Team view

### Alert fatigue: spamming low-priority findings

An attacker who can trigger low-severity alerts at volume knows the SOC will eventually mute the notification channel. Once muted, a genuine high-severity alert arrives — and nobody sees it.

**Contained narrative:**

1. Attacker creates 30 IAM users, each with an access key, over a holiday weekend. GuardDuty's `Persistence:IAMUser/User` detector fires at low severity for each new user.
2. The Slack `#soc-alerts` channel gets 30 messages in 10 minutes. Tier 1 mutes the channel.
3. Monday, the attacker uses the *real* compromised account to call `iam:AttachRolePolicy` with `AdministratorAccess` — this triggers the `Persistence:IAMUser/AdministratorAccess` finding at HIGH severity. The Slack channel is still muted.

```bash
# Attacker noise generation (run in your own sandbox only):
for i in $(seq 1 30); do
  aws iam create-user --user-name noise-${i}
  aws iam create-access-key --user-name noise-${i}
done
# Each creates a GuardDuty finding.
# SOC mutes Slack channel after the flood.

# Attacker's real action (would be HIGH sev but channel is muted):
aws iam attach-user-policy \
  --user-name compromised-real-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Defensive pairing:**
- Never mute a channel without creating a secondary routing rule (email, PagerDuty) for unchanged high-severity alerts.
- Set a "mute expiry" — Slack mute auto-expires after 24h.
- Run a weekly check: "which rules were muted, and what alerts were missed?"

**Artifacts:**
- The 30 noise `CreateUser` + `CreateAccessKey` events are all in CloudTrail.
- The channel mute event in Slack admin audit log ties to a specific Tier 1 analyst.
- The missed `AttachRolePolicy` call is in CloudTrail but went un-acknowledged.

## 🔵 Blue Team view

### Severity-weighted alert routing

Never send everything to one channel. Matrix:

| Alert Source | Severity | Channel | On-call | Ack deadline |
|---|---|---|---|---|
| GuardDuty findings | >= 7 | PagerDuty + Slack `#soc-p0` | Primary + Secondary | 15 min |
| Sentinel incidents | High | Slack `#soc-alerts` + Teams | Primary | 30 min |
| SCC findings | Critical | PagerDuty | Primary | 15 min |
| Custom sigma rules | Medium | Jira ticket auto-create | None | 24 hr |
| Cloud Custodian violations | High | Slack `#soc-alerts` | Primary | 30 min |
| All findings | Low | Elastic dashboard tile only (review weekly) | None | 7 days |

### Alert volume dashboard (Elastic / Kibana)

```
# Elastic query — alert volume by day, by source
POST alerts-*/_search
{
  "size": 0,
  "aggs": {
    "per_day": {
      "date_histogram": { "field": "@timestamp", "calendar_interval": "1d" },
      "aggs": {
        "by_source": {
          "terms": { "field": "source.keyword", "size": 10 }
        }
      }
    }
  }
}
```

### MTTD / MTTR metrics

| Metric | Definition | Target | Current quarter |
|---|---|---|---|
| MTTD (Mean Time to Detect) | Time from event to alert creation | < 5 min | — |
| MTTA (Mean Time to Acknowledge) | Time from alert to Tier 1 ack | < 15 min | — |
| MTTR (Mean Time to Resolve) | Time from alert to incident closure | < 4 hours (high sev) | — |
| Alert-to-Noise Ratio | High-sev true positives / total alerts | > 30% | — |

### Tabletop exercise framework

Monthly, pick one rule and run a tabletop:

1. **Inject:** Manually trigger the rule (benign) — send test GuardDuty finding via EventBridge test event.
2. **Observe:** Does the alert appear in Slack within 5 minutes?
3. **Triage:** Can Tier 1 locate the investigation dashboard link?
4. **Escalate:** Can Tier 2 query the relevant log source (CloudTrail Lake / Log Analytics / BigQuery)?
5. **Contain:** Can Tier 3 execute the runbook steps successfully?
6. **Document:** Was the Jira/ServiceNow incident created with all required fields?

## Hands-on lab

1. Create a Slack incoming webhook (or use a local staging endpoint):
```bash
# Slack: https://api.slack.com/apps → Create New App → Incoming Webhooks
# Copy the webhook URL.
```

2. Deploy a Lambda that posts to Slack when an EventBridge test event fires:
```bash
aws events put-rule --name test-alert-rule \
  --event-pattern '{"source":["lab.test"],"detail-type":["Lab Alert"]}'

aws events put-targets --rule test-alert-rule \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:111111111111:function:slack-alert-guardduty"
```

3. Send a test event:
```bash
aws events put-events \
  --entries '[{"Source":"lab.test","DetailType":"Lab Alert","Detail":"{\"severity\":7,\"type\":\"Test:SecurityAlert\",\"accountId\":\"111111111111\",\"resource\":{\"instanceDetails\":{\"instanceId\":\"i-test\"}},\"id\":\"test-123\"}"}]'
```

4. Verify the Slack message arrives.

5. **Teardown:**
```bash
aws events remove-targets --rule test-alert-rule --ids 1
aws events delete-rule --name test-alert-rule
aws lambda delete-function --function-name slack-alert-guardduty
```

## Detection rules & checklists

```
# Checklist
- [ ] Every high-severity finding routes to a human-visible channel (Slack/PagerDuty)
- [ ] Runbooks stored in git alongside detection rules (version-controlled)
- [ ] Monthly tabletop exercise run for top-5 critical rules
- [ ] MTTD / MTTA / MTTR metrics tracked in a dashboard
- [ ] Alert volume reviewed weekly; muted rules documented with expiry
- [ ] Auto-remediation playbooks tested in sandbox before production
- [ ] Lambda / Logic App / Cloud Function error logs monitored (dead letter queue)
- [ ] Webhook endpoint credentials stored in Secrets Manager / Key Vault / Secret Manager
```

## References
- [AWS EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html)
- [Sentinel SOAR playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/automation)
- [Azure Logic Apps](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview)
- [GCP Cloud Functions with Pub/Sub](https://cloud.google.com/functions/docs/tutorials/pubsub)
- [PagerDuty event integration](https://developer.pagerduty.com/docs/events-api-v2/trigger-events/)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
- [../IAM/permission-boundaries-and-quarantine.md](../IAM/permission-boundaries-and-quarantine.md)
