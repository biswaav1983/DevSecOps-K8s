package main

deny[msg] {
  input.kind == "Service"
  input.spec.type != "NodePort"
  msg := "Service type should be NodePort"
}

deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.containers[0].securityContext.runAsNonRoot != true
  msg := "Containers must not run as root - use runAsNonRoot within container security context"
}

