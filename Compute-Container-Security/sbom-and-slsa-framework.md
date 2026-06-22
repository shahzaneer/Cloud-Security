# 11 — SBOM & SLSA Framework

> **Level:** Intermediate
> **Prereqs:** [Image Signing & Admission Controllers](image-signing-and-admission-controllers.md)
> **Clouds:** AWS · Azure · GCP · OnPrem
> **MITRE ATT&CK (tactics):** Initial Access, Execution, Persistence (Supply Chain Compromise — T1195)
> **Authorization scope:** Run only in your own sandbox accounts. SBOM tools scan your own container images and repositories.

## What & why

An SBOM (Software Bill of Materials) is a machine-readable inventory of every component, library, and dependency in a software artifact. SLSA (Supply-chain Levels for Software Artifacts, pronounced "salsa") is a graduated framework (Levels 0–4) that defines increasing assurances against tampering. Together they answer: "Do I know what's in this container, and can I prove nobody tampered with the build?" US Executive Order 14028 (May 2021) mandates SBOMs for federal software suppliers.

## The OnPrem reality

On-prem supply chain tracking was manual: spreadsheet-based license audits, no cryptographic provenance on build artifacts, and dependency resolution was whatever `pip install` or `npm install` pulled at build time. An attacker who compromised a build server owned every artifact produced, with no technical means to detect it.

## Core concepts

### SBOM standards

| Standard | Format | Ecosystem | Adoption (as of June 2026) |
|---|---|---|---|
| SPDX | Tag-value, JSON, RDF | Linux Foundation, ISO/IEC 5962 | Federal, enterprise |
| CycloneDX | XML, JSON, Protocol Buffers | OWASP | Container, AppSec |
| SWID | XML | NIST, ISO/IEC 19770-2 | Asset management |

### SLSA levels

| Level | Name | Requirements | Protects against |
|---|---|---|---|
| 0 | No guarantees | No SLSA compliance | Nothing |
| 1 | Provenance exists | Build process documented, provenance generated | Accidental error |
| 2 | Hosted build platform | Build on a managed platform (GitHub Actions, GCB) with source + build provenance | Tampering after build |
| 3 | Hardened build platform | Isolated ephemeral builds, non-falsifiable provenance, auditable build steps | Compromise of build platform |
| 4 | Hermetic + two-person review | Two-party approval, hermetic builds (no network), reproducible | Insider threat, build platform compromise |

### In-toto attestations

in-toto is a CNCF graduated project that creates a verifiable chain of custody from source code to artifact, known as a supply chain attestation.

```
Source ──[test]──> Build ──[sign]──> Package ──[verify]──> Deploy
  │                  │                   │                    │
  └── attestation ───┴── attestation ────┴── attestation ────┘
```

## AWS

### Generating SBOMs in AWS CI

```bash
# Syft — generate SBOM for a container image (CycloneDX JSON)
syft your-account.dkr.ecr.us-east-1.amazonaws.com/app:latest \
  -o cyclonedx-json > sbom.json

# Trivy — scan and generate SBOM
trivy image --format cyclonedx \
  your-account.dkr.ecr.us-east-1.amazonaws.com/app:latest > sbom.json

# Push SBOM to ECR alongside the image
aws ecr put-image-scanning-configuration \
  --repository-name app-repo \
  --image-scanning-configuration scanOnPush=true
```

**Gotcha:** ECR basic scanning (free) checks for CVEs but does not generate or store SBOMs. Enhanced scanning via Inspector ($1.50/image/month as of June 2026) includes SBOM generation. You can also store SBOMs as OCI artifacts in ECR using `oras`.

### SLSA Level 3 on AWS

```yaml
# GitHub Actions workflow (runs on a managed platform = SLSA 2 baseline)
name: Build and attest
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t app:latest .
      - name: Generate provenance (SLSA 3)
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: app:latest
          registry-username: ${{ secrets.ECR_USERNAME }}
      - name: Generate SBOM
        run: syft app:latest -o spdx-json > sbom.spdx.json
      - name: Sign SBOM with Cosign
        run: |
          cosign attest --key cosign.key \
            --predicate sbom.spdx.json \
            --type spdx \
            your-account.dkr.ecr.us-east-1.amazonaws.com/app:latest
```

## Azure

```bash
# ACR has built-in SBOM generation (as of June 2026, preview)
az acr show-usage --name yourregistry

# Generate SBOM with Syft for ACR image
syft yourregistry.azurecr.io/app:latest -o spdx-json > sbom.json

# Attach SBOM as an OCI artifact
oras attach yourregistry.azurecr.io/app:latest \
  --artifact-type application/spdx+json \
  sbom.json:application/spdx+json

# Defender for Containers scans ACR images
az security pricing create \
  --name Containers \
  --tier standard
```

**Gotcha:** ACR Tasks can run Syft/Trivy during build as a multi-step task. The SBOM must be attached or stored separately — ACR does not natively store SBOM metadata alongside images (as of June 2026).

### SLSA on Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  - main
pool:
  vmImage: ubuntu-latest
steps:
  - task: Docker@2
    inputs:
      command: build
      repository: app
      tags: latest
  - script: |
      syft app:latest -o cyclonedx-json > sbom.json
      cosign attest --key cosign.key --predicate sbom.json \
        --type cyclonedx yourregistry.azurecr.io/app:latest
    displayName: Generate and sign SBOM
```

## GCP

```bash
# Artifact Registry vulnerability scanning (on push)
gcloud artifacts repositories create app-repo \
  --repository-format docker \
  --location us-central1

# Generate SBOM with Syft
syft us-central1-docker.pkg.dev/project-id-111111/app-repo/app:latest \
  -o spdx-json > sbom.json

# Binary Authorization with attestation (SLSA 3)
gcloud container binauthz attestations sign-and-create \
  --artifact-url "us-central1-docker.pkg.dev/project-id/app-repo/app@sha256:abc..." \
  --attestor projects/project-id/attestors/build-attestor \
  --pgp-key-fingerprint "ABCD1234..."
```

**Gotcha:** GCP Binary Authorization can enforce that only attested images run in GKE. Combine this with SLSA provenance (in-toto attestation) stored in Artifact Registry — GKE admission will reject unsigned images.

### SLSA on Google Cloud Build

```yaml
steps:
  - name: gcr.io/cloud-builders/docker
    args: ['build', '-t', 'us-central1-docker.pkg.dev/$PROJECT_ID/app-repo/app:$COMMIT_SHA', '.']
  - name: gcr.io/$PROJECT_ID/syft
    args: ['us-central1-docker.pkg.dev/$PROJECT_ID/app-repo/app:$COMMIT_SHA', '-o', 'spdx-json']
  - name: gcr.io/$PROJECT_ID/cosign
    args: ['attest', '--key', 'cosign.key', '--predicate', '/workspace/sbom.json',
           '--type', 'spdx', 'us-central1-docker.pkg.dev/$PROJECT_ID/app-repo/app:$COMMIT_SHA']
```

## OnPrem mapping (recap table)

| Concern | OnPrem | AWS | Azure | GCP |
|---|---|---|---|---|
| SBOM format | SPDX / CycloneDX (same standards) | ECR + Inspector / Syft | ACR (preview) + Syft | Artifact Registry + Syft |
| Provenance generation | Manual signing | SLSA GitHub Generator + Cosign | Cosign attest | Binary Auth + in-toto |
| Policy enforcement | None standard | ECR image scanning rules | Defender for Containers | Binary Authorization + GKE |
| Vulnerability DB | Local VulnDB | Inspector CVEs | Defender CVEs + Qualys feed | Artifact Analysis CVEs |
| Supply chain integrity | Code signing (manual) | Sign with KMS + Cosign | Sign with Key Vault + Cosign | Sign with Cloud KMS + Cosign |
| Regulatory mandate | EO 14028 (US federal suppliers) | Same — applies to SaaS on AWS | Same | Same |

## 🔴 Red Team view

Supply chain attacks that an SBOM ecosystem would have detected or limited:

### Technique 1 — Dependency confusion (xz-style)

An attacker publishes a malicious package with the same name as a private internal package to a public registry. The build system resolves the public (attacker-controlled) version instead of the internal one. An SBOM generated at build time would show the package source (public registry URL vs internal), creating an audit trail the attacker cannot erase.

```bash
# SBOM reveals the attack:
syft image:latest -o spdx-json | jq '.packages[] | select(.name == "internal-lib") | .supplier'
# Output: "Organization: npm-public-registry" ← WRONG — should be internal
```

### Technique 2 — Build pipeline compromise (SolarWinds-analog)

An attacker compromises the CI/CD platform and injects malicious code during the build step. At SLSA Level 3, the build runs in an isolated ephemeral environment with a non-falsifiable provenance attestation. Any deviation from the approved build steps creates an attestation mismatch. At SLSA Level 4, a second human must approve the build — the attacker must compromise two independent entities.

### Technique 3 — Tampered base image

An attacker publishes a backdoored version of `ubuntu:22.04` to a registry that mirrors Docker Hub. The build CI pulls the compromised image. SBOM inspection at deploy time shows the digest differs from the known-good digest:

```bash
diff <(syft my-app:latest -o spdx-json | jq '.packages[].versionInfo') \
     <(syft ubuntu:22.04@sha256:known-good-digest -o spdx-json | jq '.packages[].versionInfo')
# Mismatch = tampering detected
```

**Artifacts left:** The SBOM generated at build time is immutable (or it should be). Compare build-time SBOM to deploy-time SBOM — any drift indicates post-build tampering.

## 🔵 Blue Team view

### CI pipeline — SBOM generation at build

Every build MUST produce:
1. A signed provenance attestation (in-toto, SLSA Level 2 minimum).
2. An SBOM in CycloneDX or SPDX format.
3. A cosign attestation linking the SBOM to the image digest.

```bash
# Minimum CI step (GitHub Actions example)
- name: Generate and sign SBOM
  run: |
    syft $IMAGE -o cyclonedx-json > sbom.json
    cosign attest --key cosign.key \
      --predicate sbom.json \
      --type cyclonedx \
      $IMAGE
    # Store SBOM in OCI-compatible registry
    oras push $REGISTRY/sbom:${GITHUB_SHA} sbom.json
```

### Policy enforcement at admission

```yaml
# OPA/Kyverno policy: reject images without signed SBOM
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-cosign-attestation
      match:
        any:
        - resources:
            kinds:
            - Pod
      verifyImages:
      - imageReferences:
        - "*"
        attestations:
        - predicateType: "https://cyclonedx.org/schema"
          conditions:
            all:
            - key: "{{ components[].name }}"
              operator: AllIn
              value: ["openssl", "libssl"]
              message: "Crypto libraries not in approved list"
```

### SBOM scanning in CI — vulnerability policy

```bash
# Trivy: fail build if CRITICAL CVEs in SBOM
trivy image --severity CRITICAL --exit-code 1 \
  --format cyclonedx --output sbom.json your-image:latest

# Grype: check against known vulnerabilities
grype sbom:sbom.json --fail-on critical
```

### Regulatory compliance — US EO 14028

- All software sold to US federal agencies must provide an SBOM (as of June 2026, enforcement is phased: critical software → all software).
- SBOMs must be machine-readable (SPDX or CycloneDX).
- The SBOM must enumerate:
  - Component name, version, supplier
  - Dependency relationships
  - Known unknowns (components the supplier cannot identify)

## Hands-on lab

1. Install Syft and Cosign:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign
```

2. Pull a public image and generate an SBOM:
```bash
docker pull nginx:alpine
syft nginx:alpine -o cyclonedx-json > nginx-sbom.json
```

3. Inspect the SBOM — find all OpenSSL versions:
```bash
jq '.components[] | select(.name | test("openssl")) | {name, version}' nginx-sbom.json
```

4. Generate a keypair and sign the image with the SBOM:
```bash
cosign generate-key-pair
cosign sign --key cosign.key nginx:alpine
cosign attest --key cosign.key --predicate nginx-sbom.json --type cyclonedx nginx:alpine
```

5. Verify the signed attestation:
```bash
cosign verify-attestation --key cosign.pub --type cyclonedx nginx:alpine
```

**Teardown:** Delete local key material (`cosign.key`, `cosign.pub`), remove local image (`docker rmi nginx:alpine`). No cloud resources created.

## Detection rules & checklists

**Kyverno policy — deny images without SBOM attestation:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom-attestation
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-sbom
      match:
        resources:
          kinds: [Pod]
      verifyImages:
      - image: "*"
        key: |-
          -----BEGIN PUBLIC KEY-----
          ...
        attestations:
        - predicateType: https://cyclonedx.org/schema
          condition:
            all:
            - key: "{{ length(components) }}"
              operator: GreaterThan
              value: 0
```

**Checklist:**
- [ ] Every production container image has a signed SBOM in CycloneDX or SPDX format.
- [ ] CI pipeline fails the build if SBOM generation fails.
- [ ] SBOMs are stored immutably in an OCI-compatible registry or dedicated artifact store.
- [ ] Vulnerability scanning runs against the SBOM in CI (Trivy/Grype).
- [ ] Production clusters enforce signed attestation via Kyverno/OPA/Binary Authorization.
- [ ] SBOMs are generated and stored for third-party images used in production.
- [ ] SLSA level is documented per artifact; target SLSA 3 for production containers.

## References
- [SLSA Framework](https://slsa.dev/)
- [SPDX Specification (ISO/IEC 5962:2021)](https://spdx.dev/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [in-toto Attestation Framework](https://in-toto.io/)
- [US Executive Order 14028 — Improving the Nation's Cybersecurity](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
- [Anchore Syft](https://github.com/anchore/syft)
- [Cosign (Sigstore)](https://github.com/sigstore/cosign)
- [MITRE ATT&CK — Supply Chain Compromise (T1195)](https://attack.mitre.org/techniques/T1195/)
