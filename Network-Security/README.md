# Module 01 — Network Security (Cloud + Infra)

Covers network-layer attack/detect for cloud: segmentation, gateways, DNS, egress control, DDoS, side-channel, and Zero Trust. Treats the network as both connectivity and as a *policy enforcement plane* — In cloud, network rules *are IAM-adjacent security controls.

## Learning objectives

- Design defensible VPC/VNet/VPC networks with explicit egress controls.
- Explain why default-deny NACL/SG/NSG/Firewall is non-negotiable.
- Detect public exposure, DNS exfil, and SSRF→IMDS pivot.
- Compare WAF, DDoS, and edge controls across AWS/Azure/GCP.
- Model Zero Trust beyond marketing fluff.

## Lessons

- [x] `vpc-segmentation-design.md`
- [x] `sg-nacl-nsg-firewall-rules.md`
- [x] `egress-and-nat-control.md`
- [x] `ip-vs-identity-zero-trust.md`
- [x] `load-balancers-and-waf.md`
- [x] `dns-routing-and-exfil-channels.md`
- [x] `ddos-and-edge-protection.md`
- [x] `peering-transit-and-private-endpoints.md`
- [x] `ssrf-and-imds-pivots.md`
- [x] `labs/egress-owner-lab.md`
- [x] `detections/dns-exfil-detection.md`

