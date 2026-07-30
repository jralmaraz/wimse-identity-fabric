terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

provider "aws" {
  region = var.aws_region
}

# ─── GCP: Identity Provider + Workload A + Token Exchange ─────────────────────

resource "google_compute_firewall" "wimse" {
  name    = "wimse-allow-inbound"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "8080", "8090", "9000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["wimse-gcp"]
}

resource "google_compute_instance" "wimse_gcp" {
  name         = "wimse-gcp"
  machine_type = "e2-micro"
  zone         = "${var.gcp_region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }

  tags = ["wimse-gcp"]

  metadata = {
    ssh-keys       = "debian:${file(var.ssh_public_key_path)}"
    startup-script = file("${path.module}/../scripts/gcp-startup.sh")
  }
}

# ─── AWS: Workload B ──────────────────────────────────────────────────────────

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "wimse" {
  name        = "wimse-workload-b"
  description = "Allow SSH and workload-b traffic"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Workload B plain HTTP"
    from_port   = 9001
    to_port     = 9001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Workload B mTLS"
    from_port   = 9443
    to_port     = 9443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "wimse_aws" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  key_name               = var.aws_key_pair_name
  vpc_security_group_ids = [aws_security_group.wimse.id]
  user_data              = file("${path.module}/../scripts/aws-startup.sh")

  tags = {
    Name = "wimse-aws"
  }
}
