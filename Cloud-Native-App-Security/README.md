# Module 07 — Cloud-Native Application Security

The application lives inside the cloud and consumes cloud primitives (storage, queues, managed DBs, identity providers). This module is OWASP grounded but for the *cloud-era* archetype: API gateway fronting serverless / containers, OAuth2 to IdP, SSRF→cloud-metadata, broken object-level authz, event-driven poisoning.

## Learning objectives

- Threat-model a serverless / microservices app against cloud-specific abuse cases.
- Identify application↔cloud misintegrations (SSRF→IMDS, SigV4 forwarding, Overscoped Audience, IAM viaLambda).
- Implement Xamarin-style auth (OAuth, OIDC, JWT, mTLS) on managed gateways across clouds.
- Detect and prevent abuse of managed queues/topics.
- Distinguish *application* vulns from *configuration/identity* vulns in a cloud breach.

## Lessons

- [x] `cloud-app-threat-model.md`
- [x] `api-gateway-and-edge-patterns.md`
- [x] `oauth-oidc-and-jwt-in-cloud.md`
- [x] `serverless-event-injection.md`
- [x] `ssrf-and-cloud-metadata-from-app.md`
- [x] `iam-from-application-context.md`
- [x] `broken-object-level-authz-and-idors.md`
- [x] `queue-topic-and-messaging-abuse.md`
- [x] `supply-chain-and-3p-integrations.md`
- [x] `api-security-testing-dast.md`
- [x] `labs/ssrf-to-imds-lab.md`
- [x] `detections/ssrf-metadata-detection.md`

