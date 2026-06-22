# Detection 01 — DNS Exfiltration Detection Rules

> **Level:** Advanced
> **Prereqs:** 01-06
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Exfiltration (T1048), Command and Control (T1071.004)
**Authorization scope:** Run detection queries only in your own environment / log workspace.

## Overview

This file contains Sigma-style detection rules and cloud-native query examples for detecting DNS-based data exfiltration. All example domains use the placeholder `*.example.net` as required by the curriculum. Adapt the domain patterns to your threat intelligence feeds.

## Detection signals

DNS exfiltration leaves four primary signals:

| Signal | Threshold | False positive risk |
|--------|-----------|-------------------|
| High entropy in subdomain labels | Shannon entropy > 4.5 | Moderate — CDN hostnames, AWS service names |
| Long FQDN (>100 chars) | Single-label > 52 chars, total > 150 chars | Low — very few legitimate FQDNs exceed 150 chars |
| Unusual query volume | > 500 queries/min from single source IP | Moderate — legitimate DNS-heavy apps |
| TXT record query spike | > 50 TXT queries/10 min from single source | Low — TXT queries are rare in normal ops |

---

## Sigma-style detection rules

### Rule 1: High-entropy subdomain query

```yaml
title: DNS Exfiltration - High Entropy Subdomain
id: 00000000-0000-0000-0000-000000000001
status: experimental
description: Detects DNS queries with base64-like entropy in subdomain labels
author: lab
date: 2026-06-22
tags:
  - attack.exfiltration
  - attack.t1048
logsource:
  category: dns
  product: cloud
detection:
  selection:
    query_name|re: '^[A-Za-z0-9+/=_-]{30,}\.example\.net$'
  filter:
    query_type: 'TXT'
  condition: selection and not filter
falsepositives:
  - CDN hostnames with random prefixes
  - DKIM/SPF DNS records
level: high
```

### Rule 2: Large TXT record response

```yaml
title: DNS Exfiltration - Large TXT Response
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Detects TXT record responses larger than 255 bytes suggesting data exfiltration
author: lab
date: 2026-06-22
tags:
  - attack.exfiltration
  - attack.t1048
logsource:
  category: dns
  product: cloud
detection:
  selection:
    query_type: 'TXT'
    response_size|gt: 255
  timeframe: 5m
  condition: selection | count() by src_ip > 10
falsepositives:
  - SPF records (these are typically large)
  - DKIM key lookups
level: medium
```

### Rule 3: Rapid DNS queries to same domain

```yaml
title: DNS Exfiltration - Query Burst to Single Domain
id: 00000000-0000-0000-0000-000000000003
status: experimental
description: Detects >100 DNS queries per minute from a single host to a single domain tree
author: lab
date: 2026-06-22
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource:
  category: dns
  product: cloud
detection:
  selection:
    query_name|endswith: '.example.net'
  timeframe: 1m
  condition: selection | count() by src_ip, query_name > 100
falsepositives:
  - DNS-based load balancing health checks
  - Misconfigured applications retrying DNS
level: high
```

### Rule 4: Non-standard record type queries

```yaml
title: DNS Exfiltration - Unusual Record Types
id: 00000000-0000-0000-0000-000000000004
status: experimental
description: Detects queries for NULL, CNAME, or ANY record types associated with tunneling
author: lab
date: 2026-06-22
tags:
  - attack.exfiltration
  - attack.t1048
logsource:
  category: dns
  product: cloud
detection:
  selection:
    query_type:
      - 'NULL'
      - 'ANY'
  filter:
    query_type: 'A'
  timeframe: 10m
  condition: selection | count() by src_ip > 5
falsepositives:
  - DNSSEC validation queries
  - Legitimate debugging tools
level: medium
```

---

## Cloud-native detection queries

### AWS CloudWatch Logs Insights (Route 53 Resolver Query Logs)

```
fields @timestamp, srcaddr, query_name, query_type
| filter strlen(query_name) > 100
| filter query_name like /\.example\.net$/
| stats count() as queries by srcaddr, query_name
| sort queries desc
| limit 20
```

Long subdomain detection with entropy calculation:

```
fields @timestamp, srcaddr, query_name
| filter query_name like /\.example\.net$/
| parse query_name /^(?<subdomain>[^.]+)\.example\.net$/
| filter strlen(subdomain) > 30
| stats count() by srcaddr, subdomain
| sort count desc
```

TXT record anomaly:

```
fields @timestamp, srcaddr, query_name, query_type, rcode
| filter query_type = "TXT"
| filter query_name like /\.example\.net$/
| stats count() by srcaddr, bin(5m) as window
| filter count > 20
```

### Azure Log Analytics (Azure DNS / Private Resolver)

```kusto
// High-volume queries to a single domain
AzureDiagnostics
| where Category == "DnsQueryLogs"
| where Name contains ".example.net"
| summarize QueryCount = count() by SrcIp = SourceSystem, Name, bin(TimeGenerated, 1m)
| where QueryCount > 100
| project TimeGenerated, SrcIp, Name, QueryCount
| order by QueryCount desc
```

Long FQDN detection:

```kusto
AzureDiagnostics
| where Category == "DnsQueryLogs"
| where strlen(Name) > 150
| project TimeGenerated, SourceSystem, Name, RecordType
```

TXT record burst:

```kusto
AzureDiagnostics
| where Category == "DnsQueryLogs"
| where RecordType == "TXT"
| summarize TXTCount = count() by SrcIp = SourceSystem, bin(TimeGenerated, 10m)
| where TXTCount > 50
| join kind=leftouter (
    AzureDiagnostics
    | where Category == "DnsQueryLogs"
    | where RecordType == "TXT"
    | project TimeGenerated, SourceSystem, Name
) on $left.SrcIp == $right.SourceSystem
| project TimeGenerated, SrcIp, Name, TXTCount
```

### GCP Cloud Logging (Cloud DNS Logs)

High entropy subdomain:

```
resource.type="dns_managed_zone"
logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
jsonPayload.queryName =~ "^[A-Za-z0-9+/=_-]{30,}\\.example\\.net\\.?$"
jsonPayload.queryType != "TXT"
```

Query volume spike (>500/min from single compute instance):

```
resource.type="dns_managed_zone"
logName="projects/PROJECT_ID/logs/dns.googleapis.com%2Fdns_queries"
jsonPayload.queryName =~ ".*\\.example\\.net\\.?$"
severity >= DEFAULT
```

Aggregate by source IP — use Logs Explorer or BigQuery export for statistical analysis:

```sql
SELECT
  jsonPayload.sourceIp,
  jsonPayload.queryName,
  COUNT(*) as query_count,
  TIMESTAMP_TRUNC(timestamp, MINUTE) as minute
FROM `project.dataset.dns_logs`
WHERE jsonPayload.queryName LIKE '%.example.net%'
GROUP BY jsonPayload.sourceIp, jsonPayload.queryName, minute
HAVING query_count > 100
ORDER BY query_count DESC
```

### OnPrem (BIND query log → syslog)

```bash
# Long subdomain labels
rg 'query:.*\s([A-Za-z0-9+/=_-]{30,})\.example\.net\s' /var/log/syslog

# TXT record volume per source IP
rg 'query:.*TXT.*example\.net' /var/log/syslog | \
  awk '{print $3}' | sort | uniq -c | sort -rn | awk '$1 > 50'
```

---

## Alert thresholds (tuning guide)

| Environment | Threshold | Rationale |
|-------------|-----------|-----------|
| Small VPC (< 50 instances) | 50 queries/min from single IP | Low baseline |
| Medium VPC (50-500 instances) | 200 queries/min from single IP | Moderate noise |
| Large / auto-scaling | 500 queries/min from single IP + entropy check | High baseline, rely on entropy |

Start with the low threshold in `LOG`/`ALERT` mode, observe false positives for one week, then dial up to the appropriate threshold for `BLOCK` mode.

## Integration with SIEM

### Splunk (from AWS CloudWatch → Splunk HEC)

```spl
index=dns source="route53_resolver"
| eval fqdn_length=len(query_name)
| where fqdn_length > 100
| table _time, srcaddr, query_name, query_type, fqdn_length
```

### Elasticsearch / ELK

```json
{
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "query_name": "*.example.net" } },
        { "script": { "script": "doc['query_name.keyword'].value.length() > 100" } }
      ]
    }
  }
}
```

## Response playbook when alert fires

1. **Verify:** Check the query logs for the exact `query_name` and source IP. Is the pattern sustained or a one-off?
2. **Correlate:** Check VPC Flow Logs for outbound connections from the same source IP. Is there parallel HTTPS exfiltration?
3. **Contain:** If confirmed, isolate the instance — change its SG to deny all outbound traffic or detach it from the VPC
4. **Block:** Update DNS Firewall / RPZ / response policy to block the exfiltration domain
5. **Investigate:** Check CloudTrail/Activity Log for IAM API calls from the instance role — what data could have been accessed?
6. **Remediate:** Patch the SSRF / RCE vulnerability that allowed the initial compromise
7. **Post-incident:** Add the exfiltration domain to your blocklist permanently; tune detection thresholds

## Sample alert configuration (AWS CloudWatch Alarm)

```hcl
resource "aws_cloudwatch_log_metric_filter" "dns_exfil_length" {
  name           = "dns-exfil-long-fqdn"
  pattern        = "{ $.query_name = \"*.example.net*\" }"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name

  metric_transformation {
    name      = "DNSExfilLongFQDN"
    namespace = "Security/DNS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dns_exfil" {
  alarm_name          = "dns-exfil-alert"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DNSExfilLongFQDN"
  namespace           = "Security/DNS"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "DNS exfiltration - long FQDN queries detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

## Expected false positives and exclusions

- **CDN distribution hostnames:** `d111111abcdef8.cloudfront.net` — add `*.cloudfront.net` and equivalent CDN domains to exclusions
- **AWS/Cloud API endpoints:** `sqs.us-east-1.amazonaws.com` — add cloud provider domains to whitelist
- **Container registry:** `111111111111.dkr.ecr.us-east-1.amazonaws.com` — long but legitimate
- **Health check probes:** Regular DNS queries from load balancers — exclude LB IPs from source
- **Certificate validation (ACME):** `_acme-challenge` TXT records — exclude these specific patterns

## References

- [AWS Route 53 Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html)
- [Azure DNS Private Resolver diagnostics](https://learn.microsoft.com/en-us/azure/dns/private-resolver-logging-diagnostics)
- [GCP Cloud DNS logging](https://cloud.google.com/dns/docs/monitoring)
- [Sigma rule format](https://sigmahq.io/docs/basics/rules.html)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
