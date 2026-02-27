provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "example" {
  bucket = "cloudrisk-sentinel-example-bucket-REPLACE-ME"

  tags = {
    Name        = "CloudRisk Example"
    Environment = "Dev"
  }
}

# Enforce bucket owner ownership (recommended modern default)
resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Block all forms of public access
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Enable versioning (often recommended by scanners/best practice)
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket" "example" {
    replication_configuration {
        role = aws_iam_role.replication.arn
        rules {
            id = "foobar"
            prefix = "foo"
            status = "Enabled"
            
            destination {
                bucket = aws_s3_bucket.destination.arn
                storage_class = "STANDARD"
            }
        }

    }
}

# Enable default encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master-key-id = aws_key_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Enforce TLS-only access (deny non-HTTPS)
data "aws_iam_policy_document" "tls_only" {
  statement {
    sid = "DenyInsecureTransport"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.example.arn,
      "${aws_s3_bucket.example.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.tls_only.json
}
resource "aws_s3_bucket_logging" "example" {
   bucket = aws_s3_bucket.example.id

   target_bucket = aws_s3_bucket.log_bucket.id
   target_prefix = "log/"
 }