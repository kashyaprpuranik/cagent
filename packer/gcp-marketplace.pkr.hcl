packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = ">= 1.1.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project ID to build the image in"
  # No default — must be provided at build time
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "image_family" {
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

source "googlecompute" "cagent" {
  project_id          = var.project_id
  zone                = var.zone
  machine_type        = "e2-standard-4"
  source_image_family = "ubuntu-2404-lts-amd64"
  source_image_project_id = ["ubuntu-os-cloud"]
  ssh_username        = "packer"
  disk_size           = 50
  disk_type           = "pd-ssd"
  image_name          = "cagent-marketplace-{{timestamp}}"
  image_family        = var.image_family
  image_description   = "Cagent data plane for GCP Marketplace"
  image_labels = {
    managed-by = "packer"
    purpose    = "cagent-marketplace"
  }
}

build {
  sources = ["source.googlecompute.cagent"]

  provisioner "file" {
    source      = "${path.root}/../scripts/gcp-first-boot.sh"
    destination = "/tmp/gcp-first-boot.sh"
  }

  provisioner "file" {
    source      = "${path.root}/../scripts/gcp-first-boot.service"
    destination = "/tmp/gcp-first-boot.service"
  }

  provisioner "shell" {
    script = "${path.root}/scripts/provision.sh"
    environment_vars = [
      "CAGENT_REPO=${var.cagent_repo}",
      "CAGENT_BRANCH=${var.cagent_branch}",
    ]
  }
}
