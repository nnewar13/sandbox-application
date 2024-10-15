terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.0"
    }
  }
}

provider "aws" {
  shared_credentials_files = ["${path.module}/.aws/credentials"]
}

# setup aws iam policy document
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# setup lambda IAM role
resource "aws_iam_role" "sandbox_lambda_role" {
  name               = "terraform_sandbox_lambda_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags = {
    key   = "Owner"
    value = "Nischal Newar"
  }
}

# setup iam polcy for lambda logging
resource "aws_iam_policy" "sandbox_lambda_logging" {
  name        = "terraform_sandbox_lambda_logging"
  description = "policy created to provide log permissions using terraform"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : "logs:CreateLogGroup",
        "Resource" : "arn:aws:logs:us-east-1:600627358874:*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "arn:aws:logs:us-east-1:600627358874:log-group:/aws/lambda/terraform_sandbox_lambda_function:*"
        ]
      }
    ]
  })
}

# attach the iam policy to role
resource "aws_iam_role_policy_attachment" "sandbox_lambda_attachment" {
  role       = aws_iam_role.sandbox_lambda_role.name
  policy_arn = aws_iam_policy.sandbox_lambda_logging.arn
}


# setup lambda archive file
data "archive_file" "sandbox_lambda_file" {
  type        = "zip"
  source_file = "${path.module}/src/terraform_lambda.py"
  output_path = "${path.module}/src/terraform_lambda_function_payload.zip"
}

# create log group
resource "aws_cloudwatch_log_group" "sandbox_lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.sandbox_lambda_function.function_name}"
  retention_in_days = 1
  lifecycle {
    prevent_destroy = false
  }
}

# create the lambda function
resource "aws_lambda_function" "sandbox_lambda_function" {
  filename         = data.archive_file.sandbox_lambda_file.output_path
  function_name    = "terraform_sandbox_lambda_function"
  role             = aws_iam_role.sandbox_lambda_role.arn
  handler          = "terraform_lambda.lambda_handler"
  depends_on       = [aws_iam_role_policy_attachment.sandbox_lambda_attachment, aws_cloudwatch_log_group.sandbox_lambda_log_group ]
  source_code_hash = data.archive_file.sandbox_lambda_file.output_base64sha256
  runtime          = "python3.9"
  tags = {
    key   = "Owner"
    value = "Nischal Newar"
  }
}

# create the api gateway
resource "aws_api_gateway_rest_api" "sandbox_apigateway" {
  name = "terraform_sandbox_apigateway"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  tags = {
    key   = "Owner"
    value = "Nischal Newar"
  }
}

# create api gateway resource
resource "aws_api_gateway_resource" "sandbox_apigateway_resource" {
  rest_api_id = aws_api_gateway_rest_api.sandbox_apigateway.id
  parent_id   = aws_api_gateway_rest_api.sandbox_apigateway.root_resource_id
  path_part   = "sandbox_lambda"
}

# create api gateway method
resource "aws_api_gateway_method" "sandbox_apigateway_method" {
  rest_api_id   = aws_api_gateway_rest_api.sandbox_apigateway.id
  resource_id   = aws_api_gateway_resource.sandbox_apigateway_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

# link apigateway and lambda
resource "aws_api_gateway_integration" "sanbodx_apigateway_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.sandbox_apigateway.id
  resource_id             = aws_api_gateway_resource.sandbox_apigateway_resource.id
  http_method             = aws_api_gateway_method.sandbox_apigateway_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.sandbox_lambda_function.invoke_arn
}

# apigateway lambda invoke permission integration
resource "aws_lambda_permission" "sandbox_apigateway_lambda_permisison" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sandbox_lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.sandbox_apigateway.execution_arn}/*"
}

# create api gateway response
resource "aws_api_gateway_method_response" "sandbox_apigateway_method_response" {
  rest_api_id = aws_api_gateway_rest_api.sandbox_apigateway.id
  resource_id = aws_api_gateway_resource.sandbox_apigateway_resource.id
  http_method = aws_api_gateway_method.sandbox_apigateway_method.http_method
  status_code = "200"
}

# create integration response
resource "aws_api_gateway_integration_response" "sandbox_apigateway_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.sandbox_apigateway.id
  resource_id = aws_api_gateway_resource.sandbox_apigateway_resource.id
  http_method = aws_api_gateway_method.sandbox_apigateway_method.http_method
  status_code = aws_api_gateway_method_response.sandbox_apigateway_method_response.status_code
  depends_on  = [aws_api_gateway_integration.sanbodx_apigateway_lambda_integration]
}

# create api gateway deployment
resource "aws_api_gateway_deployment" "sandbox_apigateway_deployment" {
  rest_api_id = aws_api_gateway_rest_api.sandbox_apigateway.id
  depends_on  = [aws_api_gateway_integration.sanbodx_apigateway_lambda_integration]
  stage_name  = "terraform_sandbox_stage"
}

# create dynamo db
resource "aws_dynamodb_table" "sandbox_dynamodb_table" {
  name = "terraform_sandbox_dynamodb"
  billing_mode = "PROVISIONED"
  read_capacity = 20
  write_capacity = 20
  hash_key = "UserID"
  range_key = "UserTitle"

  attribute {
    name = "UserID"
    type = "S"
  }

  attribute {
    name = "UserTitle"
    type = "S"
  }

  attribute {
    name = "UserName"
    type = "S"
  }

  attribute {
    name = "Courses"
    type = "S"
  }

  attribute {
    name = "Grade"
    type = "N"
  }

  global_secondary_index {
    name = "CoursesIndex"
    hash_key = "Courses"
    range_key = "Grade"
    write_capacity = 10
    read_capacity = 10
    projection_type = "INCLUDE"
    non_key_attributes = ["UserID"]
  }

  tags = {
    key = "Owner"
    value = "Nischal Newar"
  }
}