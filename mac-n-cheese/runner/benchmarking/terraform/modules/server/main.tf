terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.15"
    }
  }
}

variable "name" {
  description = "the name of this server"
}
variable "aws_instance_type" {
  description = "the aws instance type to use"
}
variable "allow_incoming_proof_requests_from_cidr" {
  description = "the cidr of our peer"
}
variable "allow_ssh_from" {
  description = "the cidr to allow ssh from"
}
variable "ssh_public_key" {
  description = "the SSH public key to allow"
}
variable "volume_size" {
  description = "Size of the volume in gibibytes (GiB)"
}

data "aws_ami" "amazon_linux" {
  owners = ["amazon"]
  most_recent = true
  filter {
    name = "name"
    values = ["amzn2-ami-kernel-5.10-hvm-2.0.*-x86_64-gp2"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_key_pair" "keypair" {
  key_name = format("%s%s", "sieve-benchmarking-tmp-", var.name)
  public_key = var.ssh_public_key
}

resource "aws_security_group" "zk_server_security_group" {
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = [var.allow_ssh_from]
    ipv6_cidr_blocks = []
  }
  ingress {
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = [var.allow_incoming_proof_requests_from_cidr]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "tls_private_key" "zk_server_host_key" {
  algorithm = "RSA"
  rsa_bits = "4096"
}

resource "aws_instance" "zk_server" {
  ami = "${data.aws_ami.amazon_linux.id}"
  instance_type = var.aws_instance_type
  vpc_security_group_ids = [aws_security_group.zk_server_security_group.id]
  key_name = aws_key_pair.keypair.id
  user_data = templatefile("${path.module}/cloud-init.yml", {
    priv_key = tls_private_key.zk_server_host_key.private_key_pem
    pub_key = tls_private_key.zk_server_host_key.public_key_openssh
  })
  instance_initiated_shutdown_behavior = "terminate"
  
  root_block_device {
    volume_size = var.volume_size
  }

  tags = {
    Name = var.name
  }
}

output "public_ip" { value = aws_instance.zk_server.public_ip }
output "host_public_key" { value = tls_private_key.zk_server_host_key.public_key_openssh }

