#!/usr/bin/env python3
import sys
sys.path = ['.'] + sys.path
sys.path = ['./modules'] + sys.path
import boto3
import configparser
import argparse
from os.path import expanduser
from botocore.config import Config
from datetime import datetime
##########################################################################
# awsconfigfile: The file where this script will store the credentials
awsconfigfile = '/.aws/credentials'

# Input Variables
parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("-c","--code",default='default',type=str,help="The MFA code",required=True)
requiredNamed.add_argument("-s","--serial-number",type=str,help="The identification number (ARN) of the MFA device that is associated with the IAM user making the call",required=True)
requiredNamed.add_argument("-m","--mfa-profile",type=str,help="The name of the profile which the credentials will be saved to",required=True)
optionalNamed = parser.add_argument_group('optional named arguments')
optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The profile to use when making the get-session-token call (defaults to default)")
optionalNamed.add_argument("-d","--duration",default=43200,type=int,help="The session duration to assume the role for (default to 43200 seconds (12hrs), min is 900s (15min) and the max is 129600s (36hrs))")
optionalNamed.add_argument("--region",default='af-south-1',type=str,help="The default region for the session profile (defaults to af-south-1)")
optionalNamed.add_argument("--output-format",default='json',type=str,help="The default output format for the session profile (defaults to json) ")

# Parse the variables into an options dict
args = parser.parse_args()
options = {}
options['TokenCode']=args.code
options['SerialNumber']=args.serial_number
options['DurationSeconds']=args.duration

# Fetch the session tokens
session = boto3.Session(profile_name=args.profile)
token = session.client('sts',config=Config()).get_session_token(**options)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into the credentials file
if not config.has_section(args.mfa_profile):
    config.add_section(args.mfa_profile)

config.set(args.mfa_profile, 'output', args.output_format)
config.set(args.mfa_profile, 'region', args.region)
config.set(args.mfa_profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set(args.mfa_profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set(args.mfa_profile, 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print ('\n\n----------------------------------------------------------------')
print ('Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'.format(filename,args.mfa_profile))
print ('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
print ('After this time, you may safely rerun this script to refresh your access key pair.')
print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(args.mfa_profile))
print ('----------------------------------------------------------------\n\n')
