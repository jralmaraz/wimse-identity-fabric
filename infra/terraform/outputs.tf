output "gcp_ip" {
  description = "External IP of the GCP VM (runs IdP, Workload A, Token Exchange)"
  value       = google_compute_instance.wimse_gcp.network_interface[0].access_config[0].nat_ip
}

output "aws_ip" {
  description = "Public IP of the AWS VM (runs Workload B)"
  value       = aws_instance.wimse_aws.public_ip
}

output "gcp_ssh" {
  description = "SSH command for the GCP VM"
  value       = "gcloud compute ssh debian@wimse-gcp --zone=${var.gcp_region}-a"
}

output "aws_ssh" {
  description = "SSH command for the AWS VM (replace path to your key)"
  value       = "ssh -i ~/.ssh/<your-key>.pem ec2-user@${aws_instance.wimse_aws.public_ip}"
}
