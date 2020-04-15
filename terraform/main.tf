provider "apigee" {
  org          = var.apigee_organization
  access_token = var.apigee_token
}

terraform {
  backend "azurerm" {}

  required_providers {
    apigee = "~> 0.0"
    archive = "~> 1.3"
  }
}

module "identity-service" {
  source             = "github.com/NHSDigital/api-platform-service-module"
  name               = "identity-service"
  path               = "identity-service"
  apigee_environment = var.apigee_environment
  proxy_type         = "live"
  namespace          = var.namespace
}
