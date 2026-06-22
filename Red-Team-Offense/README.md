# Module 09 — Red Team: Cloud Offense

The offense career that a DevOps engineer never had reason to learn. Post-exploitation, credential theft, lateral in the cloud, C2 alternatives (Lambda/Functions-as-C2), cradle-to-grave persistence, evasion of *commercial* detection, and the "build your own simple APT" labs (lab-bounded).

> ⚠️ All lessons require explicit scope and consent framing. Member your authorised sandbox accounts only.

## Learning objectives

- Approach cloud offense as credential-first, exploit-late.
- Enumerate without leaving persistent footprint — prefer built-in tools over traditional malware.
- Project assume-role chains across clouds to detangle blast radius.
- Use serverless-as-C2 / "serverless living-off-the-cloud" thinking (educational, scaffolding only).
- Demo reduce-in-forensic-noise techniques (User-Agent, region-normalization, trail-free actions).
- Map every offensive step to its corresponding detection + control (covered Module-by-module's Blue sections).

## Lessons

- [x] `methodology-and-PTES-for-cloud.md`
- [x] `recon-osint-and-fingerprint.md`
- [x] `initial-access-vectors.md`
- [x] `credential-theft-and-token-physics.md`
- [x] `privilege-escalation-catalogue.md`
- [x] `lateral-movement-and-pivoting.md`
- [x] `persistence-techniques-in-cloud.md`
- [x] `evasion-and-trail-free-actions.md`
- [x] `collection-data-exfil-channels.md`
- [x] `serverless-as-c2-and-living-off-the-land.md`
- [x] `building-a-simple-apt.md`
- [x] `labs/linchpin-lab.md`
- [x] `labs/simple-apt-lab.md`
- [x] `detections/cloud-tuxy-baseline-detection.md`

