#!/usr/bin/env python3

import sys

# TODO:
#   PRE-CHECK: test that $HOME/.aws/ directory exists or create|fail
#   CHECK: Username must be prefixed with DOMAIN in the format "CORP\" (vs "COPR/" or empty)

# Let the script know where to find modules
# add entry to the from of the list of paths
# to give locally installed modules preference
sys.path = ['.'] + sys.path
sys.path = ['./modules'] + sys.path
import boto3
import requests
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import getpass
from bs4 import BeautifulSoup
from os.path import expanduser
from botocore.config import Config

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'eu-west-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)

##########################################################################

# Get the federated credentials from the user

import argparse

parser = argparse.ArgumentParser()

optionalNamed = parser.add_argument_group('Option Named Arguments')
optionalNamed.add_argument('-s','--saml_response',type=str,help="The SAML response from the SSO IDP to use to auth to AWS")

args = parser.parse_args()

import urllib.parse

assertion = urllib.parse.unquote(args.saml_response)

if 'SAMLResponse=' in assertion:
    assertion = assertion.split('SAMLResponse=')[1]


# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print ("")
#print([role.split(',')[0].split(':')[4] for role in awsroles])
#exit
#if len(awsroles) > 1:
#    i = 0
#    print ("Please choose the role you would like to assume:")
#    for awsrole in awsroles:
#        print ('[', i, ']: ', awsrole.split(',')[0])
#        i += 1
#    print ("Selection: ",  end=" ")
#    selectedroleindex = input()
#
#    # Basic sanity check of input
#    if int(selectedroleindex) > (len(awsroles) - 1):
#        print ('You selected an invalid role index, please try again')
#        sys.exit(0)
#
#    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
#    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
#else:
#    role_arn = awsroles[0].split(',')[0]
#    principal_arn = awsroles[0].split(',')[1]


for selectedroleindex in range(len(awsroles)):
    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    print(role_arn)
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    profile_name = role_arn.split(':')[4] + '-' + role_arn.split('/')[1]


    # Use the assertion to get an AWS STS token using Assume Role with SAML
    token = boto3.client('sts',config=Config()).assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=assertion,
        DurationSeconds=28800
        )

    # Write the AWS STS token into the AWS credential file
    home = expanduser("~")
    filename = home + awsconfigfile

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(filename)

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile_name):
        config.add_section(profile_name)

    config.set(profile_name, 'output', outputformat)
    config.set(profile_name, 'region', region)
    config.set(profile_name, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set(profile_name, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set(profile_name, 'aws_session_token', token['Credentials']['SessionToken'])

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    print ('\n\n----------------------------------------------------------------')
    print ('Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'.format(filename,profile_name))
    print ('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
    print ('After this time, you may safely rerun this script to refresh your access key pair.')
    print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(profile_name))
    print ('----------------------------------------------------------------\n\n')

# Use the AWS STS token to list all of the S3 buckets
s3conn = boto3.Session(
    aws_access_key_id=token['Credentials']['AccessKeyId'],
    aws_secret_access_key=token['Credentials']['SecretAccessKey'],
    aws_session_token=token['Credentials']['SessionToken'],
    region_name = region
    )

s3 = s3conn.resource('s3',config=Config())


print ('Simple API test listing all S3 buckets:')
buckets = [bucket.name for bucket in s3.buckets.all()]
print(buckets)
