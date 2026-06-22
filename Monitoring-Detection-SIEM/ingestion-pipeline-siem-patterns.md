# 06 — Ingestion Pipeline & SIEM Patterns

> **Level:** Intermediate–Advanced
> **Prereqs:** [The Security Log Mosaic per Cloud](the-security-log-mosaic-per-cloud.md), [Cloudtrail Activity & Data Events](cloudtrail-activity-and-data-events.md), [Azure Log Analytics & Sentinel](azure-log-analytics-and-sentinel.md), [GCP Cloud Audit Logs & Scc](gcp-cloud-audit-logs-and-scc.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Defense Evasion (T1562.008), Impact (T1496 — resource consumption)
> **Authorization scope:** All ingestion examples use placeholder account IDs and are for your own sandbox. Cost estimates are illustrative — verify current pricing.

## What & why

A security ingestion pipeline moves logs from each cloud's native sink to a central SIEM — Elastic, Splunk, Sentinel, or homegrown OpenSearch. The pipeline's design determines: (1) whether you can afford it (ingestion volume is the #1 SIEM cost driver), (2) how quickly alerts fire, and (3) whether logs survive an attacker who deletes the source trail. Cost management is half the battle.

## The OnPrem reality

Logstash → Elasticsearch → Kibana (ELK). Fluent-bit → Loki → Grafana. Splunk Universal Forwarder → Indexers. Syslog-ng over TCP to a collector. Pre-cloud, you controlled the total volume by limiting which hosts shipped syslog. Cloud log volume is enormous — a single VPC Flow Logs output can exceed all your on-prem syslog combined.

## Core concepts

### The ingestion chain

```
[CloudTrail / Activity Log / Cloud Audit Logs]
        │
        ▼
  [Cloud sink: S3 / Log Analytics / BigQuery]
        │
        ▼
  [Shipper: Lambda / Logstash / Fluentd / Function]
        │
        ▼
  [Central SIEM: Elastic / Splunk / Sentinel / OpenSearch]
        │
        ▼
  [Dashboards + Alerts]
```

### Tiered storage — the cost equation

| Tier | Hot | Warm | Cold |
|---|---|---|---|
| Retention | 7–30 days | 30–90 days | 90 days–7 years |
| Query speed | Sub-second | Seconds | Minutes (rehydrate first) |
| Cost per GB/month | ~$0.50–$2.00 | ~$0.10–$0.50 | ~$0.01–$0.03 |
| Stores | Security alerts, raw threat events | Full activity logs (1 month) | Full activity logs (years) |
| SIEM mapping | Elastic hot nodes, Splunk hot buckets | Elastic warm nodes, Splunk warm | S3 / GCS / Blob → search on demand |

### Ingestion cost drivers per cloud (approx)

| Cloud | Log source | Approx volume for a 50-instance env | Estimated monthly cost in SIEM |
|---|---|---|---|
| AWS | CloudTrail mgmt events | ~2 GB/month | Low |
| AWS | S3 data events (all buckets) | ~50–200 GB/month | High — use selective enablement |
| AWS | VPC Flow Logs (ALL traffic) | ~500 GB–2 TB/month | Very high — sample or aggregate |
| Azure | Activity Log | ~1 GB/month | Low |
| Azure | NSG Flow Logs (ALL) | ~200 GB–1 TB/month | Very high — use sampling |
| GCP | Admin Activity | ~2 GB/month | Low |
| GCP | Data Access (all services) | ~20–100 GB/month | Medium-high |
| All | GuardDuty/SCC/Defender findings | ~50 MB/month | Negligible |

## AWS → Elastic SIEM pipeline

### Step 1: CloudTrail → S3 → SQS → Logstash

```hcl
resource "aws_sqs_queue" "cloudtrail" {
  name = "cloudtrail-notifications"
}

resource "aws_s3_bucket_notification" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  queue {
    queue_arn = aws_sqs_queue.cloudtrail.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_lambda_function" "cloudtrail_to_es" {
  filename      = "cloudtrail_to_es.zip"
  function_name = "cloudtrail-to-es"
  role          = aws_iam_role.lambda_es.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  environment {
    variables = {
      ES_ENDPOINT = "https://search-es-siem-xxxx.us-east-1.es.amazonaws.com"
      ES_INDEX    = "cloudtrail-%{+YYYY.MM.dd}"
    }
  }
}
```

Minimal Lambda handler (Elastic SIEM / OpenSearch):

```python
import boto3
import json
import gzip
import requests
from requests_aws4auth import AWS4Auth

es_host = "https://search-es-siem-xxxx.us-east-1.es.amazonaws.com"

def handler(event, context):
    s3 = boto3.client('s3')
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        response = s3.get_object(Bucket=bucket, Key=key)
        logs = json.loads(gzip.decompress(response['Body'].read()))
        for log_entry in logs.get('Records', []):
            doc_id = log_entry['eventID']
            requests.post(
                f"{es_host}/cloudtrail-2026/_doc/{doc_id}",
                auth=AWS4Auth('AKIAIOSFODNN7EXAMPLE', 'secret...', 'us-east-1', 'es'),
                json=log_entry
            )
```

### Step 2: VPC Flow Logs → CloudWatch → Lambda → Elastic

```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-id vpc-11111111 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name vpc-flow-logs

aws logs put-subscription-filter \
  --log-group-name vpc-flow-logs \
  --filter-name vpc-to-es \
  --filter-pattern "" \
  --destination-arn arn:aws:lambda:us-east-1:111111111111:function:vpc-flow-to-es
```

### Step 3: CloudWatch Dashboard for SIEM ingestion health

```
fields @timestamp, @message
| filter @message like /ERROR|FAIL|timeout/
| stats count() as errors by bin(5m)
| filter errors > 0
```

## Azure → Sentinel / Elastic pipeline

### Azure Event Hub as shipper hub

```bash
az eventhubs namespace create \
  --name security-events \
  --resource-group rg-sec-monitor \
  --location eastus \
  --sku Standard

az eventhubs eventhub create \
  --name cloudtrail-analogue \
  --namespace-name security-events \
  --resource-group rg-sec-monitor \
  --partition-count 4
```

Then configure diagnostic settings to ship to Event Hub:

```bash
az monitor diagnostic-settings create \
  --name activity-to-eventhub \
  --resource /subscriptions/00000000-0000-0000-0000-000000000000 \
  --event-hub cloudtrail-analogue \
  --event-hub-rule RootManageSharedAccessKey \
  --logs '[{"category":"Administrative","enabled":true}]'
```

Logstash config to consume from Event Hub:

```conf
input {
  azure_event_hubs {
    event_hub_connections => ["Endpoint=sb://security-events.servicebus.windows.net/;..."]
    storage_connection    => "DefaultEndpointsProtocol=https;AccountName=...;..."
    threads               => 4
    decorate_events       => true
  }
}

filter {
  json { source => "message" }
}

output {
  elasticsearch {
    hosts      => ["https://search-es-siem:9200"]
    index      => "azure-activity-%{+YYYY.MM.dd}"
    user       => "elastic"
    password   => "${ES_PASSWORD}"
    ssl        => true
  }
}
```

## GCP → Elastic / Splunk pipeline

### Pub/Sub → Dataflow → Elastic / Splunk

```bash
gcloud pubsub topics create cloudaudit-stream
gcloud logging sinks create audit-to-pubsub \
  pubsub.googleapis.com/projects/project-id-111111/topics/cloudaudit-stream \
  --log-filter='logName:"cloudaudit.googleapis.com"'
```

Dataflow streaming pipeline (Apache Beam Python) to push to Elastic:

```python
import apache_beam as beam
from apache_beam.options.pipeline_options import PipelineOptions
import json
import requests

class PushToElastic(beam.DoFn):
    def process(self, element):
        log_entry = json.loads(element)
        doc_id = log_entry.get('insertId', '')
        requests.post(
            'https://search-es-siem:9200/gcp-audit/_doc/',
            json=log_entry,
            auth=('elastic', 'PLACEHOLDER_PASSWORD')
        )
        yield log_entry

options = PipelineOptions(streaming=True, runner='DataflowRunner',
    project='project-id-111111', temp_location='gs://dataflow-temp-111111/tmp')
with beam.Pipeline(options=options) as p:
    (p | 'Read from Pub/Sub' >> beam.io.ReadFromPubSub(topic='projects/project-id-111111/topics/cloudaudit-stream')
       | 'Parse JSON' >> beam.Map(json.loads)
       | 'Push to Elastic' >> beam.ParDo(PushToElastic()))
```

### Alternative: Fluentd aggregator on a GCE VM

```bash
# On a GCE VM running the Fluentd forwarder
sudo apt install -y td-agent
sudo tee /etc/td-agent/td-agent.conf << 'EOF'
<source>
  @type pubsub
  project_id project-id-111111
  subscription_id cloudaudit-sub
  tag gcp.cloudaudit
</source>
<match gcp.**>
  @type elasticsearch
  host search-es-siem
  port 9200
  index_name gcp-cloudaudit-%Y.%m.%d
</match>
EOF
sudo systemctl restart td-agent
```

## OnPrem → Unified SIEM (comparison table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Shipper | Logstash, Fluentd | Lambda + SQS | Logstash + Event Hub | Dataflow + Pub/Sub or Fluentd |
| Central store | Elasticsearch | OpenSearch / Elastic on EC2 | Sentinel (managed SIEM) | Elastic on GCE |
| Free-tier SIEM | Elastic free + Kibana | OpenSearch free tier (t2.small) | Sentinel pay-as-you-go trial | Elastic on GCE f1-micro |
| Log volume control | Per-source syslog filter | Selective event selectors | Diagnostic setting per-resource | Sink filter expression |
| Retention cost strategy | Index lifecycle management | S3 → Glacier (cold) | Log Analytics data tiers | BigQuery table expiration |
| Alerting | ElastAlert / Watcher | CloudWatch Alarms | Sentinel analytics rules | Scheduled BigQuery → Pub/Sub |

## 🔴 Red Team view

### Budget-exhaustion attack: flooding the SIEM ingest pipeline

An attacker who knows the SIEM budget can flood the ingest tier with high-volume, low-signal events — causing the SIEM to either exceed budget and shut off, or age out valuable logs too quickly.

```bash
# AWS: generate thousands of ListObjects calls to flood S3 data events
for i in $(seq 1 10000); do
  aws s3api list-objects --bucket innocent-bucket-111111111111 >> /dev/null &
done
# CloudTrail data events cost: ~$1 per 1M events.
# SIEM ingest: if forwarding all data events, elastic index swells.
# 10,000 ListObjects × 100 objects each = 1M data events = $0.10 CloudTrail cost,
# but 1-2 GB in your Elastic cluster = hot tier fills up.

# Alternative: rapid AssumeRole calls (management events, default on)
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/SomeListable --role-session-name flood-1
# Repeat 10,000 times. Each is a management event logged to CloudTrail + your SIEM.
```

**Azure equivalent:** Rapid `az account list-locations` or similar read-only operations — each generates Activity Log entries.

**GCP equivalent:** `gcloud projects list`, `gcloud services list` — cheap admin API calls that each generate Admin Activity entries.

**Artifacts:**
- CloudTrail volume spike visible in CloudTrail Insights as `AnomalousActivity`.
- S3 bucket notification queue depth grows (SQS visibility timeout exceeded).
- Lambda throttles / CloudWatch Logs billing alert triggers.
- Elasticsearch cluster `_cat/nodes` shows CPU spike + `rejected` queue.

**Detection pairing:** Set CloudWatch alarms on SQS queue depth and Lambda throttle metrics.

## 🔵 Blue Team view

### Tiered ingestion architecture

```
[CloudTrail] ──→ [S3] ──→ [SQS] ──→ [Lambda pre-filter] ──→ [Hot ES (high-sev only)]     ← 7d retention
                                ├──→ [S3 raw (all events)]                              ← 365d retention
                                └──→ [Athena / Lake (forensic queries)]                   ← query-on-demand
```

**Pre-filter Lambda logic:**

```python
def should_index_hot(event):
    high_sev_events = {
        'StopLogging', 'DeleteTrail', 'DeleteBucket', 'DeleteAccessKey',
        'AuthorizeSecurityGroupIngress', 'PutBucketPolicy', 'AttachRolePolicy',
        'SetIamPolicy', 'CreateUser', 'UpdateAssumeRolePolicy'
    }
    if event.get('eventName') in high_sev_events:
        return True
    if event.get('errorCode') == 'AccessDenied':
        return True
    if event.get('userIdentity', {}).get('type') == 'Root':
        return True
    return False
```

Route high-sev events to hot SIEM tier (sub-second query), all events to S3 cold storage (rehydrate on demand).

### Detection queries for SIEM health

```
# AWS CloudWatch — Lambda throttle count > 0
fields @timestamp, @message
| filter @message like "throttle" or @message like "ERROR"

# Azure KQL — Event Hub throughput anomaly
// (as of June 2026, Event Hub metrics are in the `AzureMetrics` table;
// verify column names in your Log Analytics workspace — common metric names
// include `IncomingMessages`, `OutgoingMessages`, `ThrottledRequests`)
AzureMetrics
| where MetricName == "IncomingMessages"
| summarize IngestVolume=sum(Total) by bin(TimeGenerated, 1h)
| order by IngestVolume desc

# Elasticsearch — ingest rejection rate
curl -s 'https://search-es-siem:9200/_nodes/stats/thread_pool' | \
  jq '.nodes[].thread_pool.write | {queue, rejected, active}'
```

### Preventive controls

| Control | Mechanism |
|---|---|
| Volume spike alert | CloudWatch alarm on `NumberOfEvents` / SQS `ApproximateNumberOfMessagesVisible` > threshold |
| Budget cap | Set daily budget in Event Hub / SQS. Pause non-critical ingest if exceeded. |
| Sampling | VPC Flow Logs at 10% sampling (`--logging-flow-sampling 0.1` in GCP, `--traffic-type ACCEPT` in AWS) |
| Hot/warm/cold routing | Lambda pre-filter routes to hot index only if `severity >= HIGH` or `eventName` in threat list |
| Immutable log copy | Replicate raw logs to a separate security account before forwarding to SIEM |

### Response to volume spike

1. **Identify source:** Query CloudTrail/Activity Log for the principal and API call dominating the spike.
2. **Block:** Attach `DenyAll` inline policy or disable the principal's access keys.
3. **Sample-down:** Increase VPC Flow Log sampling rate to 50% or higher temporarily.
4. **Expand capacity:** Add warm nodes to Elastic cluster or increase Log Analytics daily cap.

## Hands-on lab — local Elastic SIEM with Filebeat

1. Start Elasticsearch + Kibana via Docker:
```bash
docker run -d --name es -p 9200:9200 -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.11.0

docker run -d --name kibana --link es:elasticsearch -p 5601:5601 \
  docker.elastic.co/kibana/kibana:8.11.0
```

2. Ship a sample CloudTrail log file via Filebeat:
```bash
# Create a sample CloudTrail JSON log file
cat > /tmp/sample-cloudtrail.json << 'EOF'
{"Records":[{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111111111111:user/dev-user","accountId":"111111111111"},"eventTime":"2026-06-22T12:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"RunInstances","sourceIPAddress":"203.0.113.42","userAgent":"aws-cli/2.0","requestParameters":{"instanceType":"t2.micro"},"responseElements":{"instancesSet":{"items":[{"instanceId":"i-11111111111111111"}]}},"requestID":"abc-123","eventID":"def-456","eventType":"AwsApiCall","recipientAccountId":"111111111111"}]}
EOF

curl -X POST "http://localhost:9200/cloudtrail-test/_doc" \
  -H "Content-Type: application/json" \
  -d @/tmp/sample-cloudtrail.json
```

3. View in Kibana → Stack Management → Index Patterns → create `cloudtrail-test*`.

4. **Teardown:**
```bash
docker stop es kibana && docker rm es kibana
rm /tmp/sample-cloudtrail.json
```

## Detection rules & checklists

```
# Checklist
- [ ] All audit logs ship to at least one central sink (S3/Log Analytics/BigQuery)
- [ ] SIEM ingest pipeline has per-source volume dashboards
- [ ] Hot/warm/cold tiering configured with defined retention policy
- [ ] Pre-filter Lambda/Function routes high-sev events to hot tier
- [ ] Volume spike alert exists (SQS depth, Lambda throttles, Event Hub limit)
- [ ] Raw logs replicated to immutable bucket before any processing
- [ ] Monthly SIEM cost review — identify highest-volume sources, adjust sampling
- [ ] Test rehydration from cold storage (replay a week-old log into Elastic)
```

## References
- [Elastic SIEM Guide](https://www.elastic.co/guide/en/siem/guide/current/index.html)
- [Splunk Cloud ingestion](https://docs.splunk.com/Documentation/SplunkCloud/latest/Data/ManagedCloudoverview)
- [OpenSearch ingestion](https://opensearch.org/docs/latest/data-ingestion/)
- [Azure Event Hub for logs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-about)
- [GCP Pub/Sub export](https://cloud.google.com/logging/docs/export)
- [../Blue-Team-Defense/blue-team-basics.md](../Blue-Team-Defense/blue-team-basics.md)
