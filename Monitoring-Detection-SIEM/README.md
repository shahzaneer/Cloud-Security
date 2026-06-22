# Module 06 — Monitoring, Detection & SIEM

Where engineering telemetry becomes security telemetry. Covers what logs each cloud actually emits, how to centralise them, how to convert "an interesting line" into a *detection rule*, and how the SOC's kill-switch (alert + auto-response) is stitched together.

## Learning objectives

- Identify the canonical security log source per cloud (CloudTrail, Activity Log/Entra audit, Cloud Audit Logs).
- Build an ingestion pipeline to a SIEM (free tier Elastic / OpenSearch / Sentinel / Splunk Free).
- Write Sigma/OPA/Cloud Custodian rules that run cross-cloud.
- Configure each cloud's native threat-detection service.
- Distinguish between Rule-level detection vs behaviour/anomaly detection.

## Lessons

- [x] `the-security-log-mosaic-per-cloud.md`
- [x] `cloudtrail-activity-and-data-events.md`
- [x] `azure-log-analytics-and-sentinel.md`
- [x] `gcp-cloud-audit-logs-and-scc.md`
- [x] `native-threat-detection-guardduty-defender-scc.md`
- [x] `ingestion-pipeline-siem-patterns.md`
- [x] `detection-as-code-sigma-and-custodian.md`
- [x] `alert-to-action-soc-tiers.md`
- [x] `entity-behaviour-ueba-basics.md`
- [x] `threat-intelligence-integration.md`
- [x] `labs/add-one-detection-lab.md`
- [x] `detections/cross-cloud-public-buckets-detection.md`

