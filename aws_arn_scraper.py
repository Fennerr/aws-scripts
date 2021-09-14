import requests
from bs4 import BeautifulSoup
import re
import os

def striphtml(data):
    p = re.compile(r'<.*?>')
    return p.sub('', data)

def parse_service(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
#check = soup.find_all('h2', id='awsaccounts-resources-for-iam-policies')[0]
    check = soup.find_all('h2', id=re.compile('resources-for-iam-policies'))[0]
    if re.search('does not support',check.next_element.next_element.next_element.contents[0]):
        #print("FAILED CHECK")
        return

    #print("PASSED CHECK")
    #print(check.next_element.next_element.next_element.contents[0])
    for arn_html in soup.find_all('div', class_='table-contents')[1].find_all('code'):
        print(striphtml(str(arn_html)))
        with open(output_file, 'a') as f:
            f.write(striphtml(str(arn_html))+'\n')

output_file = "aws_arns.txt"
try:
    os.remove(output_file)
except:
    pass

baseUrl = 'https://docs.aws.amazon.com/service-authorization/latest/reference/'
page = requests.get('https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html')
soup = BeautifulSoup(page.content, 'html.parser')
list_of_services = soup.find_all('div', class_='highlights')[0]

for i in list_of_services.find_all('li'):
    service_url = baseUrl + i.find('a').attrs['href'][2:]
    print(f'Parsing {service_url}')
    parse_service(service_url)

