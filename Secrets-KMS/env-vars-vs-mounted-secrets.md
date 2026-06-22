# 05 — Env Vars vs. Mounted Secrets

> **Level:** Intermediate
> **Prereqs:** [05-03 — Secret Stores Per Cloud](./secret-stores-per-cloud.md); ties with [03-* — Compute & Container Security](../Compute-Container-Security/)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Credential Access, Discovery
> **Authorization scope:** Run only in your own sandbox accounts against your own processes; no production targets.

## What & why

*How* a secret reaches a workload is as important as where it is stored. Environment variables are inherited by every child process, leaked in crash dumps, and dumped by `printenv` in debug endpoints. Filesystem-mounted secrets (tmpfs volumes, Kubernetes secrets) only leak if an attacker has filesystem read access to the mount point. Choosing the injection method determines the attacker's post-compromise effort to exfiltrate.

## The OnPrem reality

A systemd unit file read `/etc/secrets/db-pass` (chmod 0600, owned by the application user) via `EnvironmentFile`. The application process inherited the password as an env var. Any forked child — including subprocesses spawned for image resizing, mail sending, or logging — could read the env. A crash dump (`/var/crash/_usr_bin_myapp.0.crash`) contained the entire environment block in cleartext, exfiltratable by anyone with `journalctl` access.

```bash
# OnPrem: env var injection (the old way)
cat /etc/systemd/system/myapp.service
# [Service]
# EnvironmentFile=/etc/secrets/db-pass
# ExecStart=/usr/bin/myapp

# OnPrem: mounted secret (better)
cat /etc/systemd/system/myapp.service
# [Service]
# ExecStartPre=/bin/sh -c 'mount -t tmpfs -o size=1M secrets /run/myapp'
# ExecStartPre=/bin/cp /etc/secrets/db-pass /run/myapp/credentials
# ExecStart=/usr/bin/myapp --creds-file /run/myapp/credentials
# PrivateTmp=true
# ProtectSystem=strict
```

## Cross-cloud comparison

| Aspect | Env var injection | Mounted secret / volume |
|---|---|---|
| Visibility | Every forked process; `/proc/$PID/environ` | Only processes with FS access to mount point |
| Crash dump exposure | Full env block in core dump | Mounted file NOT in core dump (unless mmap'd) |
| Debug endpoint risk | `printenv` dumps secrets | Requires file read (`cat /mnt/secrets/*`) |
| Kubernetes | `env[].valueFrom.secretKeyRef` | `volumeMounts` + tmpfs |
| Rotation behavior | Requires process restart to pick up new value | Can use fsnotify/watch to reload without restart |
| Audit trail | No file access log | FS audit (`fanotify`, `auditd`) can log reads |
| Injection tooling | CloudFormation env, Function app settings | Lambda ephemeral storage, K8s CSI driver |
| Memory exposure | In process memory anyway after read | In process memory after read (same endpoint) |

## AWS

**Lambda — env var injection (simpler, leakier):**

```bash
# CloudFormation / SAM
Environment:
  Variables:
    DB_PASSWORD: "{{resolve:secretsmanager:production/db/app-db:SecretString:password}}"
    # Resolved at deploy time; static until next deploy

# Or via AWS CLI
aws lambda update-function-configuration \
  --function-name app-processor \
  --environment "Variables={DB_PASSWORD=placeholder-pass-123}"
```

**Lambda — Secrets Manager extension pull at runtime (better):**

```bash
# Lambda layer: AWS Parameters and Secrets Lambda Extension
# App code (Python) retrieves at cold start:
import boto3, os
session = boto3.session.Session()
client = session.client(service_name='secretsmanager', region_name='us-east-1')
secret = client.get_secret_value(SecretId=os.environ['SECRET_ARN'])
db_pass = secret['SecretString']

# Env var only holds the ARN — not the secret itself
```

**Lambda ephemeral storage (mounted file):**

```python
import json, os

# Write secret to Lambda /tmp (ephemeral, cleared between invocations)
with open('/tmp/db-creds.json', 'w') as f:
    json.dump({"password": db_pass}, f)
os.chmod('/tmp/db-creds.json', 0o600)

# Read from file
with open('/tmp/db-creds.json') as f:
    creds = json.load(f)
```

**ECS / EKS — Kubernetes secret mounted to volume:**

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: secrets
      mountPath: /mnt/secrets
      readOnly: true
  volumes:
  - name: secrets
    secret:
      secretName: db-credentials
      # Mounted as tmpfs — each key becomes a file in /mnt/secrets/
```

## Azure

**Functions — app settings (env var, leak-prone):**

```bash
# App setting = env var at runtime
az functionapp config appsettings set \
  --name func-processor \
  --resource-group security-lab \
  --settings "DB_PASSWORD=placeholder-pass-123"
```

**Functions — Key Vault reference in app settings (better):**

```bash
# App setting references Key Vault — resolved at runtime by App Service
az functionapp config appsettings set \
  --name func-processor \
  --resource-group security-lab \
  --settings "DB_PASSWORD=@Microsoft.KeyVault(SecretUri=https://lab-vault-003.vault.azure.net/secrets/production-db-password/)"

# Function must have managed identity with GET secret permission on the vault
az functionapp identity assign \
  --name func-processor \
  --resource-group security-lab

az keyvault set-policy \
  --name lab-vault-003 \
  --object-id "<managed-identity-object-id>" \
  --secret-permissions get
```

**AKS — CSI driver for Key Vault mounted secrets:**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-kv
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    keyvaultName: "lab-vault-003"
    objects: |
      array:
        - |
          objectName: production-db-password
          objectType: secret
    tenantId: "00000000-0000-0000-0000-000000000000"
---
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    volumeMounts:
    - name: secrets
      mountPath: /mnt/secrets
      readOnly: true
  volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "azure-kv"
```

## GCP

**Cloud Functions — env vars (leak-prone):**

```bash
gcloud functions deploy process-function \
  --runtime python39 \
  --set-env-vars "DB_PASSWORD=placeholder-pass-123" \
  --trigger-http
```

**Cloud Functions — Secret Manager volume mount (better):**

```bash
# Mount secret as a volume (available as file)
gcloud functions deploy process-function \
  --runtime python39 \
  --trigger-http \
  --secret-volume "mount-path=/secrets,secret=production-db-password:latest"

# Application reads:
with open('/secrets/production-db-password') as f:
    db_pass = f.read().strip()
```

**GKE — Workload Identity + Secret Manager CSI:**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: gcp-secrets
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/my-project/secrets/production-db-password/versions/latest"
        fileName: "db-password"
---
# Pod spec with volume mount
volumes:
- name: secrets
  csi:
    driver: secrets-store.csi.k8s.io
    volumeAttributes:
      secretProviderClass: "gcp-secrets"
```

## OnPrem (Vault Agent injector in K8s)

```yaml
# Vault agent sidecar — injects secrets into shared volume
apiVersion: v1
kind: Pod
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/agent-inject-secret-db-creds: "secret/data/production/db-creds"
    vault.hashicorp.com/agent-inject-template-db-creds: |
      {{- with secret "secret/data/production/db-creds" -}}
      export DB_USER={{ .Data.data.username }}
      export DB_PASS={{ .Data.data.password }}
      {{- end }}
spec:
  containers:
  - name: app
    volumeMounts:
    - name: vault-secrets
      mountPath: /vault/secrets
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Env var injection | `systemd EnvironmentFile` | Lambda env vars, ECS task def env | Function app settings | Cloud Functions `--set-env-vars` |
| Mounted file | `/etc/secrets/*` chmod 0600 | Lambda `/tmp` + extension, K8s CSI | AKS CSI driver | Cloud Functions `--secret-volume` |
| Runtime secret retrieval | Vault API call / agent sidecar | Lambda extension / SDK call | `@Microsoft.KeyVault()` reference | Secret Manager client SDK |
| Rotation reload without restart | `fsnotify` + HUP signal | Lambda cold start (natural reload) | App Service slot swap | Cloud Function cold start |
| Crash dump protection | `PrivateTmp=yes`, `ProtectSystem=strict` | Not applicable (FaaS ephemeral) | Not applicable (FaaS) | Not applicable (FaaS) |
| Process isolation | `NoNewPrivileges=yes` | Lambda sandbox | App Service sandbox | Cloud Functions sandbox |

## 🔴 Red Team view

**Process crash dump exposes environment → keys.** When a process crashes and core dumps are enabled, the entire environment variable block is captured. An attacker who can trigger a crash (e.g., via a malformed request) and read the core dump extracts secrets from memory without ever touching the filesystem.

```bash
# Contained example — on your own process only
# 1. Start a process with a secret env var
DB_PASSWORD="placeholder-secret-abc123" python3 -c "
import os, time
print('PID:', os.getpid())
time.sleep(30)
" &

PID=$!

# 2. Read env vars from /proc (no root needed for own process)
cat /proc/$PID/environ | tr '\0' '\n' | grep DB_PASSWORD
# Output: DB_PASSWORD=placeholder-secret-abc123

# 3. Core dump scenario (requires ulimit -c unlimited)
# Trigger crash, then:
strings /var/crash/core.myapp.$PID | grep DB_PASSWORD
```

**Debug endpoint exposure.** Applications with debug/status endpoints (`/debug/vars`, `/actuator/env`, `/__debug`) that dump the process environment:

```python
# Vulnerable debug endpoint (Flask example — localhost only)
@app.route('/debug/env')
def debug_env():
    import os
    return dict(os.environ)
# Returns DB_PASSWORD in response body
```

**Artifacts left by attacker exfiltrating env vars:**
- Filesystem: access to `/proc/$PID/environ` (visible in `auditd` if configured)
- Core dump: `core.$PID` file in cwd or `/var/crash`
- Network: `GET /debug/env` returning secrets (in web server access log)
- Memory: reading `/proc/$PID/mem` (requires `PTRACE` capability)

## 🔵 Blue Team view

**Defense 1: Prefer mounted secrets over env vars.**

```yaml
# Kubernetes: NEVER this:
spec:
  containers:
  - env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password

# ALWAYS this:
spec:
  containers:
  - volumeMounts:
    - name: secrets
      mountPath: /mnt/secrets
  volumes:
  - name: secrets
    secret:
      secretName: db-creds
```

**Defense 2: Linux capabilities restrictions.**

```yaml
# Kubernetes PodSecurityPolicy / Pod Security Standard
securityContext:
  capabilities:
    drop: ["ALL"]   # No CAP_SYS_PTRACE, no /proc/$PID/mem read
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

**Defense 3: Log redaction for env dumps.**

```javascript
// Winston log redaction — strip sensitive keys from log output
const winston = require('winston');

const redactSecrets = winston.format((info) => {
  const sensitiveKeys = ['password', 'secret', 'token', 'key', 'DB_PASSWORD'];
  const redact = (obj) => {
    if (typeof obj !== 'object') return obj;
    for (const key of Object.keys(obj)) {
      if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        redact(obj[key]);
      }
    }
    return obj;
  };
  return redact(info);
});

const logger = winston.createLogger({
  format: winston.format.combine(redactSecrets(), winston.format.json()),
  transports: [new winston.transports.Console()]
});
```

**Defense 4: Lambda ephemeral storage pattern.**

```bash
# Use Lambda ephemeral /tmp for secrets, not env vars
# env var holds only the secret ARN:
# SECRET_ARN=arn:aws:secretsmanager:us-east-1:111111111111:secret:production/db/app-db

# At runtime, fetch+write to /tmp, read from file
# This means env var dump exposes only the ARN, not the secret
```

**Detection signals:**
1. Access to `/proc/*/environ` by non-application users (auditd rule)
2. Core dump file creation in unexpected locations
3. HTTP requests to `/debug/env`, `/actuator/env`, `/env` endpoints (WAF/ALB logs)
4. `GetSecretValue` API call from a principal that's NOT using the Lambda extension / managed identity pattern

## Hands-on lab

```bash
# 1. Demonstrate env var leakage on your own process (macOS/Linux)
echo "#!/bin/bash
export SECRET_TOKEN='placeholder-lab-token-xyz789'
python3 -c \"
import os, time
print('PID:', os.getpid())
time.sleep(15)
\" &
PID=\$!
echo \"PID: \$PID\"
# Read env from /proc (Linux) or ps (macOS)
cat /proc/\$PID/environ 2>/dev/null | tr '\\0' '\\n' | grep SECRET_TOKEN || \
  ps eww \$PID | tr ' ' '\\n' | grep SECRET_TOKEN
kill \$PID" > /tmp/env-leak-demo.sh
bash /tmp/env-leak-demo.sh

# 2. Demonstrate mounted secret pattern
mkdir -p /tmp/secrets-lab
chmod 700 /tmp/secrets-lab
echo -n "placeholder-safe-secret" > /tmp/secrets-lab/api-key
chmod 600 /tmp/secrets-lab/api-key

# Process reads from file (env var not used)
python3 -c "
with open('/tmp/secrets-lab/api-key') as f:
    key = f.read().strip()
print('Key loaded from file (not in env)')
"
# Core dump would NOT contain the API key

# Teardown
rm -rf /tmp/secrets-lab /tmp/env-leak-demo.sh
```

## Detection rules & checklists

```yaml
# Sigma-style: /proc environ access by unexpected process
title: Process Environment Read Attempt
logsource:
  category: process_creation
detection:
  selection:
    commandLine|contains: "/proc/"
    commandLine|endswith: "/environ"
  condition: selection
  severity: medium
```

```bash
# Audit: find Lambda functions with static env var secrets (not ARN references)
aws lambda list-functions --region us-east-1 \
  --query "Functions[?Environment.Variables != null].{Name: FunctionName, Env: Environment.Variables}" \
  --output json | jq '.[] | select(.Env | keys[] | test("PASSWORD|SECRET|TOKEN|KEY"; "i"))'

# Kubernetes: find pods using envFrom secrets
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef != null) | .metadata.name'
```

## References

- [AWS Lambda Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)
- [Azure App Service Key Vault references](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references)
- [GCP Cloud Functions Secret Manager integration](https://cloud.google.com/functions/docs/configuring/secrets)
- [Kubernetes Secrets CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
- [HashiCorp Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector)
- Cross-link: [05-07 — Log Redaction & Leakage Detection](./log-redaction-and-leakage-detection.md)
