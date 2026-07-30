variable "gcp_project" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_key_pair_name" {
  description = "Name of an existing AWS EC2 key pair used for SSH access"
  type        = string
}

variable "ssh_public_key_path" {
  description = "Local path to the SSH public key to install on the GCP instance"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}
