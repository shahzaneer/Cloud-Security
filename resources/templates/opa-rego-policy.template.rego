package cloudsecurity

import future.keywords.if
import future.keywords.in

default allow := false

# ── deny[msg] — hard block ────────────────────────────────────────
# Use for violations that MUST halt deployment / admission.

deny[msg] if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := sprintf("Deployment %s must set securityContext.runAsNonRoot", [input.metadata.name])
}

# ── warn[msg] — advisory ──────────────────────────────────────────
# Use for issues that should be logged but not block.

warn[msg] if {
	some container in input.spec.template.spec.containers
	not container.resources.limits
	msg := sprintf("Container %s is missing resource limits", [container.name])
}

# ═════════════════════════════════════════════════════════════════
# Terraform-plan style input
# ═════════════════════════════════════════════════════════════════
# Ingest a terraform plan JSON (terraform show -json plan.out).
#
# deny[msg] if {
# 	some resource in input.resource_changes
# 	resource.type == "aws_s3_bucket"
# 	not resource.change.after.acl
# 	msg := sprintf("S3 bucket %s has no explicit ACL", [resource.address])
# }
#
# warn[msg] if {
# 	some resource in input.resource_changes
# 	resource.type == "aws_security_group_rule"
# 	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
# 	msg := sprintf("%s opens a port to 0.0.0.0/0", [resource.address])
# }

# ═════════════════════════════════════════════════════════════════
# Kubernetes admission review style input
# ═════════════════════════════════════════════════════════════════
# Ingest admission.k8s.io/v1 AdmissionReview objects.
#
# deny[msg] if {
# 	input.request.operation == "CREATE"
# 	input.request.object.kind == "Pod"
# 	input.request.object.spec.hostNetwork == true
# 	msg := "Pod with hostNetwork=true denied"
# }
#
# warn[msg] if {
# 	input.request.operation == "UPDATE"
# 	some container in input.request.object.spec.containers
# 	container.image
# 	not startswith(container.image, "registry.example.com/")
# 	msg := sprintf("Image %s is not from approved registry", [container.image])
# }

# ═════════════════════════════════════════════════════════════════
# Default allow
# ═════════════════════════════════════════════════════════════════
allow if {
	count(deny) == 0
}
