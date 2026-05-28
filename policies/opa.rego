package kubernetes

deny[msg] {
  input.spec.template.spec.containers[_].image == "latest"
  msg := "latest tag not allowed"
}