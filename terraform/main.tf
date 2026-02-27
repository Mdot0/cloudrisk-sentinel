provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "example" {
  bucket = "cloudrisk-sentinel-example-bucket"

  tags = {
    Name        = "CloudRisk Example Vulnerable"
    Environment = "Dev"
  }
}