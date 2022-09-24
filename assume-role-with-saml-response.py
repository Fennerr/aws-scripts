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


assertion = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVzdGluYXRpb249Imh0dHBzOi8vc2lnbmluLmF3cy5hbWF6b24uY29tL3NhbWwiIElEPSJfMmJlNTE2NWFlODliMGVjZjAxMzQ1YmYwZGM0ZmU4ZjMiIElzc3VlSW5zdGFudD0iMjAyMi0wOS0xOVQwODo0MToxMC43OTZaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL3NhbWwyP2lkcGlkPUMwMjJlMnB4czwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24geG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfODE0ZmZmZDdiNzE4NmNiOTU2YWJhNTFiNDJkZjBhM2QiIElzc3VlSW5zdGFudD0iMjAyMi0wOS0xOVQwODo0MToxMC43OTZaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXI+aHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vc2FtbDI/aWRwaWQ9QzAyMmUycHhzPC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2UgVVJJPSIjXzgxNGZmZmQ3YjcxODZjYjk1NmFiYTUxYjQyZGYwYTNkIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHM6RGlnZXN0VmFsdWU+SWdVYXlUWm1EWk9mTU82K1ZqaFNWdVRKNFY1Tm53QzNWVjczdVZBWDFMcz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+cXgvNlM2UFZDb3RiVW1PZGNkQk5ncDZLeVBjRUhtb2JRMnNLSHBBY3cvUHlIZzYvNDlkSloxa1JSbDJ5NXRCSzNOM0g2L2N3OEJSMAp4cEdSRUltL1lVNXhUUG12RTFEVGZ4MDNKSUNBNUlvc0ZqRk9nck8wVEhtSEJ5VkVRRkQySU5aUExYZVliMDFIQ3JJODJZY2UxcnBzClgxdHBjVGpPYXBYR1djbHlKaHpnR1ptQ0lRVGdWZi91Z0xKaDd4SGFubWtLbnlrYVpHTmFpZGdDVlk0L2w0dHU2QVVQd2RQRTRsSzcKNTZPaGZFUE96aVhWRisyK28xRVhOZW84UlY2NjIxNFczV1dGeHFCaWJ5bmVoa3VyNGY5ZnljeG5jWWF0d1hQeVRqTXRPSjh1a09tQwpKWkJnd1V5aVgzbWozU0tjTXJ3RlFobWJCRTN2YTY5WDF4RVhtQT09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlTdWJqZWN0TmFtZT5TVD1DYWxpZm9ybmlhLEM9VVMsT1U9R29vZ2xlIEZvciBXb3JrLENOPUdvb2dsZSxMPU1vdW50YWluIFZpZXcsTz1Hb29nbGUgSW5jLjwvZHM6WDUwOVN1YmplY3ROYW1lPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRGREQ0NBbHlnQXdJQkFnSUdBV3F5WXRqTE1BMEdDU3FHU0liM0RRRUJDd1VBTUhzeEZEQVNCZ05WQkFvVEMwZHZiMmRzWlNCSgpibU11TVJZd0ZBWURWUVFIRXcxTmIzVnVkR0ZwYmlCV2FXVjNNUTh3RFFZRFZRUURFd1pIYjI5bmJHVXhHREFXQmdOVkJBc1REMGR2CmIyZHNaU0JHYjNJZ1YyOXlhekVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENrTmhiR2xtYjNKdWFXRXdIaGNOTVRrd05URXoKTVRnd09UUXpXaGNOTWpRd05URXhNVGd3T1RReldqQjdNUlF3RWdZRFZRUUtFd3RIYjI5bmJHVWdTVzVqTGpFV01CUUdBMVVFQnhNTgpUVzkxYm5SaGFXNGdWbWxsZHpFUE1BMEdBMVVFQXhNR1IyOXZaMnhsTVJnd0ZnWURWUVFMRXc5SGIyOW5iR1VnUm05eUlGZHZjbXN4CkN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEEKTUlJQkNnS0NBUUVBMXdJdUtTRmRZMy81OFhJNHZIZ2lRazNtdWZxU1BuY1BHRHRVOWVUVkl4RzZISko0RUJpekFaYys3VFBhZk5tVApXc1BpVmhFVEsvelJrcGJWQzVxZEh3WEJSSndTNHNKM1dBVVhyUHJTT1p6NEFBNUdvZ2lUVk5MSjJZb2Z5RUhodUF5b1AxRGh5UCtVCm11TUx2OVo4bGhwLzhPcWgrS2tWVUV0QXlWRVA4QmtTdnhBTjRoRVUzQ3Q4MXVIT0REOFBsOVpGK09EMG5UODgrYnkxTTd1Y3dPZ3IKTUVGak9xNElic3hJUWRtQm8xTXNzMmJWeG1vVEQvTzZOanBXVUNoM1Z2U21aalJjVUdCWjVTNEc0Q29oSjZlNUFrTXlsdllzMWVxNgp3YklnOFFkYmxJR24vVS94YmJnODV3MVZQTVVCMkJUYlV3Zk01cEExM2t3dDFlUWo4d0lEQVFBQk1BMEdDU3FHU0liM0RRRUJDd1VBCkE0SUJBUUI1c2h1WEh3RWg1NUJzeFBwUWZleFA4YUZxTUVNaUhwRE9pMVNwWGpWMkhQN21HRHpmQVhZWkcvNDQ4Uk9kOFg2QW9tSDQKWTFQSGVHUHcwN0p1cTNRWG9aS3RhM0k0U3E3Uk1OQ2J0cHNOVjQrb1loeHpMWUJxMHZjU2lSUVYrM1pzYko4c2o5WjZPOGlMSVZCRApTaS9rOVNwN1pybzNKS3UyZDUzRVF1SDkxY3pGN29lMURlR0wrNkVKK0tIV0JnT3JCWXE1YjhOQi8wc05JSzhjSnF3VlJJNHJnZnl5CmpGd210djA1K3Z4UG9qa3ljNTk0M0NBRVV4U1lHRndLUysxYVI2UFFYUDIwc0dSYVh5M0JMUWV6eWVDWTVkNUdkVU1CVUpDN3R5ZXQKVWEyNWV2enoyRnU1ZXhuSDI1cWN6cDM4OG1XY3V2M2s5NityQmV2MHhzNms8L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5td3JAaW5kaWVmaW4uY29tPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDIyLTA5LTE5VDA4OjQ2OjEwLjc5NloiIFJlY2lwaWVudD0iaHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbCIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIyLTA5LTE5VDA4OjM2OjEwLjc5NloiIE5vdE9uT3JBZnRlcj0iMjAyMi0wOS0xOVQwODo0NjoxMC43OTZaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U+aHR0cHM6Ly9zaWduaW4uYXdzLmFtYXpvbi5jb20vc2FtbDwvc2FtbDI6QXVkaWVuY2U+PC9zYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDI6Q29uZGl0aW9ucz48c2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZVNlc3Npb25OYW1lIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6YW55VHlwZSI+bXdyQGluZGllZmluLmNvbTwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PC9zYW1sMjpBdHRyaWJ1dGU+PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6YW55VHlwZSI+YXJuOmF3czppYW06OjU5NTkxMTkxMjE0Mjpyb2xlL0dvb2dsZUxvZ2luVmlld09ubHksYXJuOmF3czppYW06OjU5NTkxMTkxMjE0MjpzYW1sLXByb3ZpZGVyL0dvb2dsZUFwcHM8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5hcm46YXdzOmlhbTo6Mzk3MDc5NTM4MDQzOnJvbGUvR29vZ2xlTG9naW5ELGFybjphd3M6aWFtOjozOTcwNzk1MzgwNDM6c2FtbC1wcm92aWRlci9Hb29nbGVBcHBzPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6YW55VHlwZSI+YXJuOmF3czppYW06OjM5NzA3OTUzODA0Mzpyb2xlL0dvb2dsZUxvZ2luVmlld09ubHksYXJuOmF3czppYW06OjM5NzA3OTUzODA0MzpzYW1sLXByb3ZpZGVyL0dvb2dsZUFwcHM8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvU2Vzc2lvbkR1cmF0aW9uIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6YW55VHlwZSI+Mjg4MDA8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjwvc2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjItMDktMTlUMDg6NDA6NDYuMDAwWiIgU2Vzc2lvbkluZGV4PSJfODE0ZmZmZDdiNzE4NmNiOTU2YWJhNTFiNDJkZjBhM2QiPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOnVuc3BlY2lmaWVkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg=='

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
        DurationSeconds=3600
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
