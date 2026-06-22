# 06 — Container & Kubernetes Forensics

> **Level:** Advanced
> **Prereqs:** [03-Container-Security](../Compute-Container-Security/), [11-03](./evidence-preservation-in-ephemeral-infra.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Persistence, Defense Evasion
> **Authorization scope:** Run only in your own sandbox cluster; all example account IDs are placeholders (`111111111111`, `00000000-0000-0000-0000-000000000000`).

## What & why

Pod forensics differs fundamentally from VM forensics: pods have a lifecycle measured in minutes, ephemeral storage that disappears with the pod, no guaranteed root access, and the shared kernel of the host node. The forensic objective is to capture `/proc`, filesystem layers, network state, and process lists *before* the pod is drained, force-deleted, or naturally rescheduled.

## The OnPrem reality

N/A — container platforms are inherently cloud/distributed. The closest analogue is LXC/LXD container forensics on a single host, but that lacks the orchestrator dimension (scheduling, services, network policies).

## Core concepts

### Pod forensic acquisition target list

| Artefact | Capture method | Persistence |
|----------|---------------|-------------|
| Process list | `kubectl exec -- ps aux` | Ephemeral — lost on pod delete |
| `/proc` filesystem | `kubectl exec -- tar -cf - /proc` | Partial — process-specific; `/proc/1/environ` useful |
| Network connections | `kubectl exec -- ss -tunap` | Ephemeral |
| Overlay filesystem layers | Node-level: `docker inspect` / `crictl inspect` + snapshot overlay dir | Survives pod delete if node preserved |
| Application logs | `kubectl logs --previous` (if pod restarted) | Lost if pod deleted; use aggregated log sink |
| Pod spec / manifest | `kubectl get pod -o yaml` | Always available from API server |
| IAM token (projected SA) | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Rotates; capture for timeline correlation |
| Container image layers | `crictl pull` + tar and store in private registry | Long-lived |

### Pod snapshot reality

There is no "pod snapshot" API. The closest workflow:

```
1. kubectl cordon <node>           — prevent new pods
2. For target pod:
   a. kubectl exec -- tar -cf - /app /tmp /proc > pod-filesystem.tar
   b. kubectl exec -- ss -tunap > pod-netstat.txt
   c. kubectl exec -- ps auxwww > pod-ps.txt
   d. kubectl get pod <name> -o yaml > pod-spec.yaml
3. Node-level: crictl inspect <container-id> → overlay layer paths
4. Node-level: tar overlay layers → upload to evidence bucket
5. Node-level: snapshot node root disk (if EBS/persistent disk)
```

## AWS (EKS)

```bash
#!/bin/bash
CLUSTER="prod-cluster"
POD_NAME="suspicious-pod"
NAMESPACE="default"
NODE=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.nodeName}')
INSTANCE_ID=$(kubectl get node $NODE -o jsonpath='{.spec.providerID}' | cut -d/ -f5)
INCIDENT_ID="inc-$(date +%s)"
EVIDENCE_BUCKET="s3://forensic-bucket-111111111111"

aws eks update-kubeconfig --name $CLUSTER --region us-east-1

echo "=== Phase 1: Cordon node ==="
kubectl cordon $NODE

echo "=== Phase 2: Capture pod artefacts ==="
kubectl exec $POD_NAME -n $NAMESPACE -- tar -cf - /proc /app /tmp 2>/dev/null | \
    aws s3 cp - "${EVIDENCE_BUCKET}/${INCIDENT_ID}/${POD_NAME}-filesystem.tar"

kubectl exec $POD_NAME -n $NAMESPACE -- ss -tunap > /tmp/${POD_NAME}-netstat.txt
kubectl exec $POD_NAME -n $NAMESPACE -- ps auxwww > /tmp/${POD_NAME}-ps.txt
aws s3 cp /tmp/${POD_NAME}-netstat.txt "${EVIDENCE_BUCKET}/${INCIDENT_ID}/"
aws s3 cp /tmp/${POD_NAME}-ps.txt "${EVIDENCE_BUCKET}/${INCIDENT_ID}/"

kubectl get pod $POD_NAME -n $NAMESPACE -o yaml > /tmp/${POD_NAME}-spec.yaml
aws s3 cp /tmp/${POD_NAME}-spec.yaml "${EVIDENCE_BUCKET}/${INCIDENT_ID}/"

echo "=== Phase 3: Node disk snapshot ==="
aws ec2 create-snapshots \
    --instance-specification InstanceId=$INSTANCE_ID \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=incident-id,Value=$INCIDENT_ID},{Key=forensic,Value=true},{Key=node,Value=$NODE}]"

echo "=== Phase 4: Overlay layer capture (node-level SSM) ==="
CONTAINER_ID=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d/ -f3)
aws ssm send-command \
    --document-name "AWS-RunShellScript" \
    --targets "Key=instanceids,Values=$INSTANCE_ID" \
    --parameters '{
        "commands": [
            "crictl inspect '"$CONTAINER_ID"' > /tmp/container-inspect.json",
            "LAYERS=$(crictl inspect '"$CONTAINER_ID"' | jq -r .status.mounts[].hostPath)",
            "tar -cf /tmp/overlay-layers.tar $LAYERS 2>/dev/null",
            "aws s3 cp /tmp/overlay-layers.tar '"${EVIDENCE_BUCKET}/${INCIDENT_ID}/overlay-layers.tar"'"
        ]
    }'

echo "=== Phase 5: Drain pod (after capture) ==="
kubectl drain $NODE --ignore-daemonsets --delete-emptydir-data --force --grace-period=30
```

**Gotcha:** EKS managed node groups use `containerd`; use `crictl` not `docker`. If the AMI is Amazon Linux 2, `crictl` is at `/usr/bin/crictl`. (as of June 2026, Bottlerocket AMIs include `crictl` at `/usr/bin/crictl` by default; verify the specific Bottlerocket variant for your node group.)

## Azure (AKS)

```bash
#!/bin/bash
CLUSTER="prod-aks"
RG="aks-rg"
POD_NAME="suspicious-pod"
NAMESPACE="default"
INCIDENT_ID="inc-$(date +%s)"
STORAGE_ACCT="forensicsacct"

az aks get-credentials --resource-group $RG --name $CLUSTER

NODE=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.nodeName}')
VMSS_INSTANCE=$(az vmss list-instances \
    --resource-group $(az aks show -g $RG -n $CLUSTER --query 'nodeResourceGroup' -o tsv) \
    --name $(echo $NODE | awk -F- '{print $1"-"$2"-"$3"-vmss"}') \
    --query "[?osProfile.computerName=='$NODE'].instanceId" -o tsv)

echo "=== Phase 1: Cordon ==="
kubectl cordon $NODE

echo "=== Phase 2: Pod capture ==="
kubectl exec $POD_NAME -n $NAMESPACE -- ps auxwww > /tmp/pod-ps.txt
kubectl exec $POD_NAME -n $NAMESPACE -- ss -tunap > /tmp/pod-netstat.txt
kubectl exec $POD_NAME -n $NAMESPACE -- tar -cf - /proc 2>/dev/null > /tmp/pod-proc.tar

az storage blob upload --account-name $STORAGE_ACCT \
    --container-name evidence --name "${INCIDENT_ID}/pod-ps.txt" \
    --file /tmp/pod-ps.txt

echo "=== Phase 3: Node disk snapshot ==="
DISK_ID=$(az vmss show --resource-group $NODE_RG --name $VMSS_NAME \
    --query "virtualMachines[?instanceId=='$VMSS_INSTANCE'].storageProfile.osDisk.managedDisk.id" -o tsv)
az snapshot create -g $RG -n "snap-node-${INCIDENT_ID}" --source $DISK_ID

echo "=== Phase 4: Drain (after capture) ==="
kubectl drain $NODE --ignore-daemonsets --delete-emptydir-data --force
```

**Gotcha:** AKS nodes are VMSS instances. Disk snapshots target the VMSS instance's OS disk. (as of June 2026, VMSS snapshot creation during an active cordon+drain will capture the disk in its current state; the drain does not affect the disk snapshot API, but the snapshot may not reflect post-eviction pod state.)

## GCP (GKE)

```bash
#!/bin/bash
CLUSTER="prod-gke"
ZONE="us-central1-a"
POD_NAME="suspicious-pod"
NAMESPACE="default"
INCIDENT_ID="inc-$(date +%s)"
BUCKET="gs://forensic-bucket"

gcloud container clusters get-credentials $CLUSTER --zone=$ZONE

NODE=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.nodeName}')

echo "=== Phase 1: Cordon ==="
kubectl cordon $NODE

echo "=== Phase 2: Pod capture ==="
kubectl exec $POD_NAME -n $NAMESPACE -- ps auxwww > /tmp/pod-ps.txt
kubectl exec $POD_NAME -n $NAMESPACE -- ss -tunap > /tmp/pod-netstat.txt
kubectl exec $POD_NAME -n $NAMESPACE -- tar -cf - /proc 2>/dev/null > /tmp/pod-proc.tar

gsutil cp /tmp/pod-ps.txt $BUCKET/$INCIDENT_ID/
gsutil cp /tmp/pod-netstat.txt $BUCKET/$INCIDENT_ID/
gsutil cp /tmp/pod-proc.tar $BUCKET/$INCIDENT_ID/

echo "=== Phase 3: Node disk snapshot ==="
NODE_INSTANCE=$(gcloud compute instances list \
    --filter="name~'^${NODE}$'" --format='value(name)')
gcloud compute disks snapshot $NODE_INSTANCE \
    --zone=$ZONE \
    --snapshot-names="snap-node-${INCIDENT_ID}" \
    --labels=incident-id=$INCIDENT_ID,forensic=true

echo "=== Phase 4: Drain ==="
kubectl drain $NODE --ignore-daemonsets --delete-emptydir-data --force
```

**Gotcha:** GKE Autopilot nodes are not exposed to the user — you cannot snapshot the node disk directly. In Autopilot, pod-level capture (exec, logs, spec export) is the only forensic option. GKE Standard allows full node-disk access.

## OnPrem mapping (recap table)

| Artefact | OnPrem (Docker) | AWS (EKS) | Azure (AKS) | GCP (GKE) |
|----------|-----------------|-----------|-------------|-----------|
| Node disk | `dd` on bare-metal host | EBS snapshot of EC2 node | Azure Disk snapshot of VMSS | Persistent disk snapshot |
| Container FS layers | `/var/lib/docker/overlay2/` | `crictl inspect` → overlay via SSM | `crictl` via Run Command | `crictl` via SSH |
| Pod process list | `docker top` | `kubectl exec -- ps` | `kubectl exec -- ps` | `kubectl exec -- ps` |
| Network state | `nsenter` + `ss` | `kubectl exec -- ss` | `kubectl exec -- ss` | `kubectl exec -- ss` |
| Service account token | Mounted secret file | Projected SA token in `/var/run/secrets/...` | Same | Same |
| Managed node-groups | N/A | EKS Managed Node Group — can snapshot node | AKS VMSS — can snapshot instance | GKE Standard node — can snapshot |
| Serverless/autopilot | N/A | Fargate — no node access | ACI — no node access | Autopilot — no node access |

## 🔴 Red Team view

Attacker techniques that make container forensics harder:

**Knativen / scale-to-zero.** If the compromised pod is behind Knative or KEDA, it scales to zero after a period of inactivity. The pods are deleted; only the `ReplicaSet` revision history survives. No `kubectl exec` target exists.

**Force-delete with zero grace period:**
```bash
kubectl delete pod compromised-pod --grace-period=0 --force
```
This removes the pod from the API server immediately, skipping `preStop` hooks. The container filesystem layers on the node remain briefly (until the kubelet garbage-collects stopped containers), but the pod object is gone — no `kubectl describe` or `kubectl logs` possible.

**Node cordon detection.** The attacker running as a DaemonSet or hostNetwork pod can watch for node cordon events:
```bash
kubectl get events --watch | grep -i cordon
```
When the node is cordoned, the attacker triggers mass-deletion of compromised pods across the cluster.

**Covering tracks in container logs.** The attacker writes null bytes to stdout, flooding log aggregation and potentially causing log rotation before forensic capture.

**Artifacts:**
- `kubectl delete pod --force` entries in the API server audit log (`audit-policy.yaml` must have `RequestResponse` level for pods).
- Container exit code `137` (SIGKILL from force-delete).
- Missing `preStop` hook execution in container lifecycle logs.

## 🔵 Blue Team view

### Audit policy: capture pod deletions

```yaml
# audit-policy.yaml — ensure pod deletion is logged at RequestResponse level
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
  verbs: ["delete", "deletecollection"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec"]
  verbs: ["create"]
```

### DaemonSet for pre-emptive pod capture

Deploy a DaemonSet that captures every pod's filesystem before the drain:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: forensic-capture
  namespace: forensic-system
spec:
  selector:
    matchLabels:
      app: forensic-capture
  template:
    metadata:
      labels:
        app: forensic-capture
    spec:
      hostPID: true
      hostIPC: true
      containers:
      - name: capture
        image: alpine:3.19
        command: ["/bin/sh", "-c"]
        args:
        - |
          while true; do
            for CID in $(crictl ps -q --state Running); do
              POD_NAME=$(crictl inspect $CID | jq -r '.status.labels."io.kubernetes.pod.name"')
              TIMESTAMP=$(date +%s)
              crictl exec $CID ps aux > /captures/${POD_NAME}-${TIMESTAMP}-ps.txt 2>/dev/null
              crictl exec $CID ss -tunap > /captures/${POD_NAME}-${TIMESTAMP}-netstat.txt 2>/dev/null
            done
            sleep 60
          done
        volumeMounts:
        - name: captures
          mountPath: /captures
        - name: run
          mountPath: /run
      volumes:
      - name: captures
        hostPath:
          path: /var/forensic-captures
      - name: run
        hostPath:
          path: /run
```

> Run only in sandbox; this captures `/proc` artefacts from every container on the node continuously.

### Log sink: immutable and read-only

```bash
# AWS: S3 bucket with Object Lock, versioned, CloudTrail-enabled on the bucket itself
# Azure: storage account with immutable blob, soft-delete enabled
# GCP: GCS bucket with retention policy, audit logs enabled

# Cluster-wide log sink (GCP example)
gcloud logging sinks create forensic-logsink \
    storage.googleapis.com/projects/${PROJECT_ID}/buckets/forensic-bucket \
    --log-filter='resource.type="k8s_container"'
```

### Post-incident node disk snapshot automation

```python
# AWS Lambda: trigger on GuardDuty K8s-related finding
def lambda_handler(event, context):
    node_name = extract_node_from_finding(event)
    instance_id = get_ec2_instance_id(node_name)
    ec2 = boto3.client('ec2')
    ec2.create_snapshots(
        InstanceSpecification={'InstanceId': instance_id},
        TagSpecifications=[{'ResourceType': 'snapshot',
            'Tags': [{'Key': 'forensic', 'Value': 'true'}]}]
    )
```

## Hands-on lab

1. Deploy a `kind` cluster locally (or `minikube`).
2. Create a pod: `kubectl run suspicious --image=alpine -- sleep 3600`.
3. Run the pod-capture script: exec `ps`, `ss`, tar `/proc`.
4. Force-delete the pod: `kubectl delete pod suspicious --grace-period=0 --force`.
5. Check `crictl ps -a` on the node — the stopped container may still exist. Capture its overlay layers.
6. Teardown: `kind delete cluster`.

## Detection rules & checklists

```yaml
title: Pod Force-Deleted With Zero Grace Period
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: delete
    objectRef.resource: pods
    requestReceivedTimestamp: <any>
  force_flag:
    responseStatus.code: 200
    # audit log request body contains gracePeriodSeconds: 0
  condition: selection and force_flag
  severity: high
  description: "Pod deleted with grace-period=0 — likely anti-forensic activity"
```

- [ ] Kubernetes audit policy set to `RequestResponse` for pod delete/exec events.
- [ ] Node disk snapshot performed within 60 seconds of alert for any GuardDuty/SCC K8s finding.
- [ ] Managed K8s ephemeral-disk limitation documented in forensic capability report.
- [ ] DaemonSet forensic capture deployed in sandbox/DR environment (not production without performance testing).

## References

- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [crictl CLI](https://github.com/kubernetes-sigs/cri-tools)
- [EKS forensic capture](https://aws.amazon.com/blogs/containers/forensic-container-checkpointing-in-amazon-eks/)
- [AKS node management](https://learn.microsoft.com/en-us/azure/aks/node-access)
- [GKE node images](https://cloud.google.com/kubernetes-engine/docs/concepts/node-images)
- See ATT&CK Cloud matrix for Execution, Defense Evasion
