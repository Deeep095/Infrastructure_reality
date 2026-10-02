# ==============================================================================
# 0. TERRAFORM PROVIDER & VARIABLES
# ==============================================================================
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "db_password" {
  type      = string
  sensitive = true
}

# ==============================================================================
# 1. NETWORKING LAYER (VPC, Subnets, IGW, NAT, Routes) - 17 Resources
# ==============================================================================
resource "aws_vpc" "prod" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "prod-vpc", Environment = "Production" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.prod.id
  tags   = { Name = "prod-igw" }
}

# Subnets
resource "aws_subnet" "public_az1" {
  vpc_id                  = aws_vpc.prod.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags                    = { Name = "prod-public-az1" }
}

resource "aws_subnet" "public_az2" {
  vpc_id                  = aws_vpc.prod.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags                    = { Name = "prod-public-az2" }
}

resource "aws_subnet" "app_az1" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.aws_region}a"
  tags              = { Name = "prod-app-az1" }
}

resource "aws_subnet" "app_az2" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.12.0/24"
  availability_zone = "${var.aws_region}b"
  tags              = { Name = "prod-app-az2" }
}

resource "aws_subnet" "data_az1" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.21.0/24"
  availability_zone = "${var.aws_region}a"
  tags              = { Name = "prod-data-az1" }
}

resource "aws_subnet" "data_az2" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.22.0/24"
  availability_zone = "${var.aws_region}b"
  tags              = { Name = "prod-data-az2" }
}

# NAT Gateways & Elastic IPs
resource "aws_eip" "nat_az1" {
  domain = "vpc"
  tags   = { Name = "prod-eip-az1" }
}

resource "aws_eip" "nat_az2" {
  domain = "vpc"
  tags   = { Name = "prod-eip-az2" }
}

resource "aws_nat_gateway" "nat_az1" {
  allocation_id = aws_eip.nat_az1.id
  subnet_id     = aws_subnet.public_az1.id
  tags          = { Name = "prod-nat-az1" }
}

resource "aws_nat_gateway" "nat_az2" {
  allocation_id = aws_eip.nat_az2.id
  subnet_id     = aws_subnet.public_az2.id
  tags          = { Name = "prod-nat-az2" }
}

# Route Tables & Routes
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.prod.id
  tags   = { Name = "prod-public-rt" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table" "private_az1" {
  vpc_id = aws_vpc.prod.id
  tags   = { Name = "prod-private-rt-az1" }
}

resource "aws_route" "private_nat_az1" {
  route_table_id         = aws_route_table.private_az1.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_az1.id
}

resource "aws_route_table" "private_az2" {
  vpc_id = aws_vpc.prod.id
  tags   = { Name = "prod-private-rt-az2" }
}

resource "aws_route" "private_nat_az2" {
  route_table_id         = aws_route_table.private_az2.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_az2.id
}

# Route Table Associations
resource "aws_route_table_association" "pub_az1" {
  subnet_id      = aws_subnet.public_az1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "pub_az2" {
  subnet_id      = aws_subnet.public_az2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "app_az1" {
  subnet_id      = aws_subnet.app_az1.id
  route_table_id = aws_route_table.private_az1.id
}

resource "aws_route_table_association" "app_az2" {
  subnet_id      = aws_subnet.app_az2.id
  route_table_id = aws_route_table.private_az2.id
}

resource "aws_route_table_association" "data_az1" {
  subnet_id      = aws_subnet.data_az1.id
  route_table_id = aws_route_table.private_az1.id
}

resource "aws_route_table_association" "data_az2" {
  subnet_id      = aws_subnet.data_az2.id
  route_table_id = aws_route_table.private_az2.id
}

# ==============================================================================
# 2. SECURITY, ENCRYPTION & ACCESS (IAM & KMS) - 4 Resources
# ==============================================================================
resource "aws_kms_key" "master_key" {
  description             = "Production Enterprise Master KMS Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = { Name = "prod-kms-key" }
}

resource "aws_iam_role" "ec2_role" {
  name = "prod-ec2-application-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "://amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "app_policy" {
  name        = "prod-app-permissions"
  description = "Allows access to app S3 assets and queue loops"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.assets.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:SendMessage"]
        Resource = [aws_sqs_queue.jobs.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_app" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.app_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "prod-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# ==============================================================================
# 3. EDGE & CONTENT DISTRIBUTION (S3 & CloudFront) - 4 Resources
# ==============================================================================
resource "aws_s3_bucket" "assets" {
  bucket        = "prod-enterprise-static-assets-dummy-12345"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets_encrypt" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.master_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "s3-assets-oac"
  description                       = "OAC for secure S3 static assets access"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Production Application Global Content Delivery Network"
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_id                = "S3Origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3Origin"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# ==============================================================================
# 4. SEGMENTED FIREWALL SECURITY GROUPS - 4 Resources
# ==============================================================================
resource "aws_security_group" "lb" {
  name        = "prod-lb-sg"
  description = "Allows incoming public web browser traffic"
  vpc_id      = aws_vpc.prod.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
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

resource "aws_security_group" "app" {
  name        = "prod-app-sg"
  description = "Isolates application to Load Balancer traffic only"
  vpc_id      = aws_vpc.prod.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "database" {
  name        = "prod-db-sg"
  description = "Strict firewall policy for backend relational database"
  vpc_id      = aws_vpc.prod.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "cache" {
  name        = "prod-cache-sg"
  description = "Strict firewall policy for caching infrastructure"
  vpc_id      = aws_vpc.prod.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
#==============================================================================
#5. COMPUTE & SCALING LAYER (ALB, ASG, Launch Templates) - 5 Resources
#==============================================================================
resource "aws_lb" "external" {
  name               = "prod-application-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = [aws_subnet.public_az1.id, aws_subnet.public_az2.id]
}
resource "aws_lb_target_group" "app_target" {
  name        = "prod-alb-target-group"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.prod.id
  target_type = "instance"
  health_check {
    path                = "/health"
    protocol            = "HTTP"
    port                = "8080"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.external.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target.arn
  }
}
resource "aws_launch_template" "app_template" {
  name_prefix   = "prod-app-launch-template-"
  image_id      = "ami-0c55b159cbfafe1f0" # Dummy Amazon Linux 2 AMI ID
  instance_type = "t3.medium"
  iam_instance_profile {
    arn = aws_iam_instance_profile.ec2_profile.arn
  }
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.app.id]
  }
  user_data = base64encode(
    <<-EOF
    #!/bin/bash
    echo "Starting enterprise node production application setup..." > /var/log/app_init.log
    EOF
  )
  lifecycle { create_before_destroy = true }
}
resource "aws_autoscaling_group" "asg" {
  name_prefix         = "prod-asg-"
  vpc_zone_identifier = [aws_subnet.app_az1.id, aws_subnet.app_az2.id]
  target_group_arns   = [aws_lb_target_group.app_target.arn]
  min_size            = 2
  max_size            = 10
  desired_capacity    = 2
  launch_template {
    id      = aws_launch_template.app_template.id
    version = "$Latest"
  }
  force_delete              = true
  health_check_type         = "ELB"
  health_check_grace_period = 300
  tag {
    key                 = "Name"
    value               = "prod-asg-worker"
    propagate_at_launch = true
  }
}
#==============================================================================
#6. STORAGE & DATA LAYER (RDS PostgreSQL & ElastiCache Redis) - 4 Resources
#==============================================================================
resource "aws_db_subnet_group" "rds" {
  name       = "prod-rds-db-subnet-group"
  subnet_ids = [aws_subnet.data_az1.id, aws_subnet.data_az2.id]
  tags       = { Name = "prod-rds-subnet-group" }
}
resource "aws_db_instance" "postgres" {
  identifier             = "prod-relational-database"
  allocated_storage      = 20
  max_allocated_storage  = 100
  db_name                = "proddb"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  username               = "dbadmin"
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.rds.name
  vpc_security_group_ids = [aws_security_group.database.id]
  multi_az               = true
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.master_key.arn
}
resource "aws_elasticache_subnet_group" "redis" {
  name       = "prod-redis-cache-subnet-group"
  subnet_ids = [aws_subnet.data_az1.id, aws_subnet.data_az2.id]
}
resource "aws_elasticache_replication_group" "cache_cluster" {
  replication_group_id       = "prod-redis-cluster"
  description                = "Production Enterprise Distributed Caching Cluster"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 2
  engine                     = "redis"
  engine_version             = "7.0"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.cache.id]
  automatic_failover_enabled = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = false
  kms_key_id                 = aws_kms_key.master_key.arn
}
#==============================================================================
#7. MESSAGING & TELEMETRY LAYER (SQS, SNS, CloudWatch) - 3 Resources
#==============================================================================
resource "aws_sqs_queue" "jobs" {
  name                      = "prod-async-job-processing-queue"
  kms_master_key_id         = aws_kms_key.master_key.id
  message_retention_seconds = 86400
  receive_wait_time_seconds = 20
}
resource "aws_sns_topic" "alerts" {
  name              = "prod-system-ops-alerts"
  kms_master_key_id = aws_kms_key.master_key.id
}
resource "aws_cloudwatch_metric_alarm" "asg_cpu_alarm" {
  alarm_name          = "prod-asg-high-cpu-utilization-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggered if application scale policy crosses 80% boundary limits"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
  alarm_actions = [aws_sns_topic.alerts.arn]
}