packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.3.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_name_prefix" {
  type    = string
  default = "cagent-marketplace"
}

variable "cagent_repo" {
  type    = string
  default = "https://github.com/kashyaprpuranik/cagent.git"
}

variable "cagent_branch" {
  type    = string
  default = "main"
}

source "amazon-ebs" "cagent" {
  region        = var.region
  instance_type = "t3.medium"
  ssh_username  = "ubuntu"

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"] # Canonical
    most_recent = true
  }

  ami_name        = "${var.ami_name_prefix}-{{timestamp}}"
  ami_description = "Cagent data plane for AWS Marketplace"
  ami_regions     = [var.region]

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 50
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name       = "${var.ami_name_prefix}-{{timestamp}}"
    managed-by = "packer"
    purpose    = "cagent-marketplace"
  }
}

build {
  sources = ["source.amazon-ebs.cagent"]

  provisioner "file" {
    source      = "${path.root}/../scripts/aws-first-boot.sh"
    destination = "/tmp/aws-first-boot.sh"
  }

  provisioner "file" {
    source      = "${path.root}/../scripts/aws-first-boot.service"
    destination = "/tmp/aws-first-boot.service"
  }

  provisioner "shell" {
    script = "${path.root}/scripts/provision.sh"
    environment_vars = [
      "CAGENT_REPO=${var.cagent_repo}",
      "CAGENT_BRANCH=${var.cagent_branch}",
      "CLOUD_PROVIDER=aws",
    ]
  }
}
