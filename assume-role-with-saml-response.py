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

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://sts.absa.co.za/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)

# proxy details
proxy = {'https': 'bc-vip.intra.absa.co.za:8080'}

##########################################################################

# Get the federated credentials from the user
assertion = 'PHNhbWxwOlJlc3BvbnNlIElEPSJfMzc3MjJhZGEtYjFlMi00OTU2LTgyMzItYjliY2Y0YWEwOGViIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMi0wOC0yM1QwODo0MzowNi43NTNaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbCIgQ29uc2VudD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNvbnNlbnQ6dW5zcGVjaWZpZWQiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9zdHMuYWJzYS5jby56YS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIiAvPjwvc2FtbHA6U3RhdHVzPjxBc3NlcnRpb24gSUQ9Il9kODZlZWUwYS0yNmQ2LTQ4MDQtOWE4Mi01MzY0NjAxYjE0MjgiIElzc3VlSW5zdGFudD0iMjAyMi0wOC0yM1QwODo0MzowNi43NTNaIiBWZXJzaW9uPSIyLjAiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48SXNzdWVyPmh0dHA6Ly9zdHMuYWJzYS5jby56YS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiIC8+PGRzOlJlZmVyZW5jZSBVUkk9IiNfZDg2ZWVlMGEtMjZkNi00ODA0LTlhODItNTM2NDYwMWIxNDI4Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiIC8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIgLz48ZHM6RGlnZXN0VmFsdWU+LzRtblNnV1RNYndDbmdnRkxTS3lBQ0NlQVRCS1ExZjRpTGtsejhOUGtIVT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+Z1JTc0lsMTNmei9NbHJXR0NyMzBZUkdNYkF6K09XMnkzZE5wcml4VVdmWW52QktFekp2M2k4bDB2cGxzcVdMdFhMWlRXanNYRUdmS2FqRm9lM1dPTTRCcTFhRW4vL0xuYVBJeDNpYzRBdHBXMDNRaDRJaHRicUxEZ0UrN1loZ3QwaDY3U25MMVU1MWx2V1JCZmtlWlJkbGh3eUkwUy9yOU5jTVpXUWF0UW5hQnNlaXBPS3RseU8raFo2VzFUQlFXRmVpMUtocW54NFdpRTNmR05QRmNhUVBXV1NjZXBIZGlWbEVCSGloQlJkTkgvTzk5NFQrMTVMVy9jWnpUSE1Gbm8wV0VtWGw5M25KZXo5eUpOUVF3em5xK3dpNjJCYkN2ZjFycXRjWmp5RjB0NURCNm9KRnlidzRJcWFHNDB3QnFITzRuVXE5ODBHUjBqWjFyVWJYdUVRPT08L2RzOlNpZ25hdHVyZVZhbHVlPjxLZXlJbmZvIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDMkRDQ0FjQ2dBd0lCQWdJUUUrN292ci9ORUpkTzE3TTZNUVQ2QVRBTkJna3Foa2lHOXcwQkFRc0ZBREFvTVNZd0pBWURWUVFERXgxQlJFWlRJRk5wWjI1cGJtY2dMU0J6ZEhNdVlXSnpZUzVqYnk1NllUQWVGdzB5TWpBek1UWXhPREl4TXpSYUZ3MHlOVEF6TVRVeE9ESXhNelJhTUNneEpqQWtCZ05WQkFNVEhVRkVSbE1nVTJsbmJtbHVaeUF0SUhOMGN5NWhZbk5oTG1OdkxucGhNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWozdGRwVU12WC82ZUpNaW9oU3lmOE95cU52MHgxSCtEWlVDK3NQNng0c0JQMjYwMXdVTWtuS0F1S1crZGNIU3dreWhHWE5veHgvMnpJTjMzQmhlN0d2MXhaMXJQZVRNV09jRXJaVE44RnI4Mno0T2txMU5CUXQrWTVjZUtva01UcXJIVDlDQkpONHFuTE90WEZkQmpBMG4wQTdSMUhNblVBUzlKOE14NjAwdjg0TExUcXdwbWthcmF1V0Z3aG81T0crVjJlcTlpMUZWQWtvSFVSaTA4S0M4bDZpMG9GZ2hNWGxDclpGajdpbWpja3JKMkF6MmdzOW95L0ZTSWRRNnFTWGNYQmNqaHdBOXFFaWFQbXB6Q09LTk1PSU9MOVRlamFtQUo3MWVZNTJKM2p1R1lGcS9VeTQ0U0VTL3lrMC96dXhlMzdxMU0zcG1WN3NzcE1tekRBUUlEQVFBQk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQWJuNk9VaCt0TUFjRFVjOEltMEtIUm82VDNXRGZJNHJYSTBxZUFQL0U2SGRqZEZHdEF0NWo4MHVtSDUzcForanV0R1lzVzZrY3o2VjczMy8wS0E2YklwNFlyeFpWdStPbzcxUFB5WUNzV3pyaVVTaVBrT2dESDk4U05TcnN6RllaSGltZ1ozcENqZDB4Vkpub1R2NThieWdMQW54NkEzdW16QWZSNC9aV2JsdDFBWTRxcWJ1K3BOSHhzaUNINHE5Vkk0YkpWZHpyejNXajBrS0ZONGlXSVZrTFJPaTQ3cUJSTkZ2SmdJdDY5UzB1MTc4MlVjeGJUWjhhTUZPenFHWVVDaWFrNks5VUkrVlhqNWkvUGE3Y2M2UVh1UVhwd0VMWmhQTXpCRnBSS3dnWitDemt0THJ2VWMyamNMWkZNaVM0WGZJQkdpTUpGOHJnMzFtMzlKbzkvPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L0tleUluZm8+PC9kczpTaWduYXR1cmU+PFN1YmplY3Q+PE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiPkNPUlBcUFRGUzAwMDg8L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMjItMDgtMjNUMDg6NDg6MDYuNzUzWiIgUmVjaXBpZW50PSJodHRwczovL3NpZ25pbi5hd3MuYW1hem9uLmNvbS9zYW1sIiAvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIyLTA4LTIzVDA4OjQzOjA2LjczN1oiIE5vdE9uT3JBZnRlcj0iMjAyMi0wOC0yM1QyMTo0MzowNi43MzdaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U+dXJuOmFtYXpvbjp3ZWJzZXJ2aWNlczwvQXVkaWVuY2U+PC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZVNlc3Npb25OYW1lIj48QXR0cmlidXRlVmFsdWU+UFRGUzAwMDhAQ29ycC5kc2FyZW5hLmNvbTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojk1NTk2OTQwMTQwMjpzYW1sLXByb3ZpZGVyL2FkZnMtY29ycCxhcm46YXdzOmlhbTo6OTU1OTY5NDAxNDAyOnJvbGUvYWRmcy1ucGludGt1bGlwYS1kZXYta3VsaXBhLWFwcC1kZXY8L0F0dHJpYnV0ZVZhbHVlPjxBdHRyaWJ1dGVWYWx1ZT5hcm46YXdzOmlhbTo6NjU3MDMxNjA2NzQwOnNhbWwtcHJvdmlkZXIvYWRmcy1jb3JwLGFybjphd3M6aWFtOjo2NTcwMzE2MDY3NDA6cm9sZS9hZGZzLW5wc2Vua3VsaXBhLWRldi1rdWxpcGEtYXBwLWRldjwvQXR0cmlidXRlVmFsdWU+PEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjoxMzg2ODI1MzM5NTM6c2FtbC1wcm92aWRlci9hZGZzLWNvcnAsYXJuOmF3czppYW06OjEzODY4MjUzMzk1Mzpyb2xlL2FkZnMtbnBrdWxpcGFzZW4tZGV2LWt1bGlwYS1hcHAtZGV2PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+PEF0dHJpYnV0ZVZhbHVlPjQzMjAwPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48L0F0dHJpYnV0ZVN0YXRlbWVudD48QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIyLTA4LTIzVDA4OjMwOjM3LjE0MloiIFNlc3Npb25JbmRleD0iX2Q4NmVlZTBhLTI2ZDYtNDgwNC05YTgyLTUzNjQ2MDFiMTQyOCI+PEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ+PC9Bc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4='

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
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    profile_name = awsroles[int(selectedroleindex)].split(',')[0].split(':')[4]

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
