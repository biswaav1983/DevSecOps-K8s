package main

# Rule 1: Enforce NodePort for Services
deny[msg] {
  input.kind == "Service"
  input.spec.type != "NodePort"
  msg := "Service type should be NodePort"
}

# Rule 2: Ensure runAsNonRoot is set to true
deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.containers[0].securityContext.runAsNonRoot
  msg := "Containers must not run as root - use runAsNonRoot within container security context"
}

