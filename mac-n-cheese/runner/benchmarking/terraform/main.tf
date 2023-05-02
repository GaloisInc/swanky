variable "aws_profile" {
  description = "Which AWS configuration profile to use? (the one you configured with `aws configure`)"
}

variable "prover_region" {
  description = "Which region does the prover live in?"
  #default = "us-east-1"
  default = "us-west-2"
}

variable "verifier_region" {
  description = "Which region does the verifier live in?"
  default = "us-west-2"
}

variable "aws_instance_type" {
  description = "What instance type should we spawn for the prover and the verifier?"
  default = "m6i.8xlarge"
}

variable "allow_ssh_from" {
  description = "the cidr to allow ssh from"
}

variable "ssh_public_key" {
  description = "the SSH public key to allow"
}

variable "volume_size" {
  description = "Size of the volume in gibibytes (GiB)"
  default = 1024
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.15"
    }
  }

  required_version = ">= 1.0.11"
}

provider "aws" {
  profile = var.aws_profile
  region = var.prover_region
  alias = "prover"
}

module "prover_server" {
  source = "./modules/server"
  name = "prover"
  aws_instance_type = var.aws_instance_type
  allow_incoming_proof_requests_from_cidr = format("%s/32", module.verifier_server.public_ip)
  allow_ssh_from = var.allow_ssh_from
  ssh_public_key = var.ssh_public_key
  volume_size = var.volume_size
  providers = {
    aws = aws.prover
  }
}

provider "aws" {
  profile = var.aws_profile
  region = var.verifier_region
  alias = "verifier"
}

module "verifier_server" {
  source = "./modules/server"
  name = "verifier"
  aws_instance_type = var.aws_instance_type
  allow_ssh_from = var.allow_ssh_from
  ssh_public_key = var.ssh_public_key
  volume_size = var.volume_size
  allow_incoming_proof_requests_from_cidr = "127.0.0.1/32" # disable this
  providers = {
    aws = aws.verifier
  }
}

output "prover_public_ip" { value = module.prover_server.public_ip }
output "verifier_public_ip" { value = module.verifier_server.public_ip }
output "prover_host_key" { value = module.prover_server.host_public_key }
output "verifier_host_key" { value = module.verifier_server.host_public_key }
