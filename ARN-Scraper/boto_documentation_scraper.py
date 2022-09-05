import requests
from bs4 import BeautifulSoup
import re
import os
import pathlib
import json

# bug: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer.html#AccessAnalyzer.Client.create_access_preview


ignored_methods = ['can_paginate','close','get_paginator','get_waiter']

def striphtml(data):
    p = re.compile(r'<.*?>')
    return p.sub('', str(data))

def parse_mainpage(url):
    page = requests_session.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    list_of_services = soup.find_all("ul", class_="current")[0]


def parse_service(url):
    page = requests_session.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
#check = soup.find_all('h2', id='awsaccounts-resources-for-iam-policies')[0]

    methods = soup.find_all("dl", class_="method")
    method_data = {}
    for method in methods:
        method_name = method.find("dt").attrs["id"].split('.')[-1]
        
        # if not method_name == 'create_cloud_formation_change_set':
        #     continue

        if method_name in ignored_methods:
            continue
        # Set rescursive = False so that we can parse nested lists
        if method.find_all("dt", class_="field-name")[0].getText() == 'Parameters':
            try:
                parameters = method.find_all("dt", class_="field-name")[0].next_sibling.find('ul').find_all('li', recursive = False)
            except AttributeError:
                # There is only 1 param, so there is no list item
                parameters = [method.find_all("dt", class_="field-name")[0].next_sibling]

            parameter_data = {}
            for parameter in parameters:
                temp = parse_parameter(parameter)
                parameter_name = temp['Name']
                del temp['Name']
                parameter_data[parameter_name] = temp
            
            method_data[method_name] = parameter_data
        else:
            # Method does not require parameters
            method_data[method_name] = 'No parameters defined'
    return method_data

def parse_parameter(parameter):
    if parameter.string == '(string) --' or parameter.getText().split('\n')[0] == '(string) --' or parameter.getText() == '(integer) --':
        return {
            "Name": None,
            "Description": None,
            "Type": "string",
            "Required": False
        }
        
    try:
        parameter_name = parameter.find('strong').contents[0]
        parameter_description = striphtml('\n'.join(str(x) for x in parameter.find_all('p', recursive = False) if not '[REQUIRED]' in str(x)))
        if not parameter_description == '':
            parameter_description = re.sub(' , ', ', ', parameter_description)
            parameter_description = re.sub(' \. ', '. ', parameter_description)
        else:
            parameter_description = ''.join(parameter.getText().split(' -- ')[1:])
        parameter_type = re.search(r'\((.*)\)',striphtml(parameter).split(' --')[0])[1]
    except Exception as e:
        print(e)
    try:
        if parameter.findChildren()[3].getText() == '[REQUIRED]' or parameter.findChildren()[2].getText() == '[REQUIRED]':
            parameter_required = True
        else:
            parameter_required = False
    except IndexError:
        parameter_required = False
    except Exception as e:
        print(e)
        parameter_required = False

    if parameter_type == 'dict':
        dict_output = {}
        dict_parameters = parameter.find('ul').find_all('li',recursive=False)
        for dict_parameter in dict_parameters:
            dict_parameter_output = parse_parameter(dict_parameter)
            dict_output[dict_parameter_output['Name']] = {
                'Description': dict_parameter_output['Description'],
                'Type': dict_parameter_output['Type'],
                'Required': dict_parameter_output['Required']
            }
        return {
            "Name": parameter_name,
            "Description": parameter_description,
            "Type": parameter_type,
            "Required": parameter_required,
            "Dict Variable": dict_output
        }
    if parameter_type == 'list':
        list_output = []
        list_parameters = parameter.find('ul').find_all('li',recursive=False)
        for list_parameter in list_parameters:
            if '(63 octets)' in ''.join([x.getText() for x in list_parameter.contents]):
                # Stupid list in https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.request_certificate (SAN parameter)
                continue
            list_parameter_output = parse_parameter(list_parameter)
            list_output.append(list_parameter_output)
        return {
            "Name": parameter_name,
            "Description": parameter_description,
            "Type": parameter_type,
            "Required": parameter_required,
            "List Variables": list_output
        }
    if parameter_type == 'string' or parameter_type == 'integer' or parameter_type == 'boolean' or parameter_type == 'datetime' or parameter_type == 'bytes':
        return {
            "Name": parameter_name,
            "Description": parameter_description,
            "Type": parameter_type,
            "Required": parameter_required
        }


def save_data(filename,data):
    # Make output dir if it doesnt exist
    output_dir = pathlib.Path(__file__).parent.absolute() / 'output'
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    with filepath.open("w") as write_file:
        json.dump(data, write_file, indent=4)



output_file = "something.txt"
try:
    os.remove(output_file)
except:
    pass

# url = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/serverlessrepo.html'
requests_session = requests.Session()
# url = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html'
# parse_service(url)

baseUrl = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/'
page = requests_session.get('https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/index.html')
soup = BeautifulSoup(page.content, 'html.parser')
list_of_services = soup.find_all("ul", class_="current")[0].findChild()



for i in list_of_services.find_all('li'):
    service_url = baseUrl + i.find('a').attrs['href']
    service_name = i.getText()
    filename = service_name + '.json'
    print(f'Parsing {service_url}')
    service_output = parse_service(service_url)
    save_data(filename,service_output)

