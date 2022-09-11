from typing import Type
import requests
from bs4 import BeautifulSoup
import re
import os
import pathlib
import json

BeautifulSoup.findChildren
# bug: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer.html#AccessAnalyzer.Client.create_access_preview

debug = False
debug_page = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer.html'
debug_method = 'create_access_preview'

ignored_methods = ['can_paginate','close','get_paginator','get_waiter']

def striphtml(data):
    p = re.compile(r'<.*?>')
    return p.sub('', str(data))

def parse_mainpage(url):
    page = requests_session.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    list_of_services = soup.find_all("ul", class_="current")[0]


def parse_service(url):
    if debug == True:
        if not url == debug_page:
            return
    page = requests_session.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
#check = soup.find_all('h2', id='awsaccounts-resources-for-iam-policies')[0]

    methods = soup.find_all("dl", class_="method")
    method_data = {}
    for method in methods:
        try:
            method_name = method.find("dt").attrs["id"].split('.')[-1]
        except KeyError:
            # Methods that have methods will get a keyerror here
            # this worked for the all() method for the resource_summaries method
            method_name = method.find("dt").find("code",class_="descname").getText()

        # print(f"Parsing method: {method_name}")s
        if debug == True:
            if not method_name == debug_method:
                continue

        if method_name in ignored_methods:
            continue
        # Set rescursive = False so that we can parse nested lists
        try: 
            if method.find_all("dt", class_="field-name")[0].getText() == 'Parameters':
                try:
                    parameters = method.find_all("dt", class_="field-name")[0].next_sibling.find('ul',class_="first simple").find_all('li', recursive = False)
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
        except:
            # Resource clients are not that well documenteted sometimes, ie the load() function in https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Bucket.load
            method_data[method_name] = 'No parameters defined'
    return method_data

def parse_parameter_orig(parameter):
    
        
    try:
        parameter_type = re.search(r'\((.*)\)',striphtml(parameter).split(' --')[0])[1]
        parameter_name = parameter.find('strong').contents[0]
        parameter_description = striphtml('\n'.join(str(x) for x in parameter.findChildren('p') if not '[REQUIRED]' in str(x)))
        if not parameter_description == '':
            parameter_description = re.sub(' , ', ', ', parameter_description)
            parameter_description = re.sub(' \. ', '. ', parameter_description)
        else:
            parameter_description = ''.join(parameter.getText().split(' -- ')[1:])
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

    if parameter_name == 'kmsKey':
        catch_me = True

    if parameter.string == '(string) --' or parameter.getText().split('\n')[0] == '(string) --':
        try:
            nested_lists = parameter.findChildren('ul')
            for nested_list in nested_lists:
                nested_parameters=nested_list.findChildren('li')
                if nested_parameters:
                    dict_output = {}
                    for nested_parameter in nested_parameters:
                        nested_parameters_output = parse_parameter(nested_parameter)
                        dict_output[nested_parameters_output['Name']] = {
                            'Description': nested_parameters_output['Description'],
                            'Type': nested_parameters_output['Type'],
                            'Required': nested_parameters_output['Required']
                        }
                    return {
                        "Name": parameter_name,
                        "Description": parameter_description,
                        "Type": "string",
                        "Required": parameter_required,
                        "String Variable": dict_output
                    }
                    # The string contains more parameters
        except:
            pass
        return {
            "Name": None,
            "Description": None,
            "Type": "string",
            "Required": False
        }
        # Need to see if the string actually contains a dict..

    if parameter.getText() == '(integer) --':
        return {
            "Name": None,
            "Description": None,
            "Type": "integer",
            "Required": False
        }

    if parameter_type == 'dict':
        dict_output = {}
        dict_parameters = parameter.find('ul').findChildren('li')
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


def parse_parameter(parameter):
    parameter_name, parameter_description, parameter_type = '','',''
        
    try:
        parameter_type = re.search(r'\((.*)\)',striphtml(parameter).split(' --')[0])[1]
        try:
            parameter_name = parameter.findChild('strong',recursive=False).contents[0]
        except AttributeError:
            parameter_name = None

        parameter_description = striphtml('\n'.join(str(x) for x in parameter.findChildren('p',recursive=False) if not '[REQUIRED]' in str(x)))
        if not parameter_description == '':
            parameter_description = re.sub(' , ', ', ', parameter_description)
            parameter_description = re.sub(' \. ', '. ', parameter_description)
        else:
            parameter_description = ''.join(parameter.getText().split(' -- ')[1:])
    except Exception as e:
        print(e)
    try:
        if parameter.findChildren(recursive=False)[3].getText() == '[REQUIRED]' or parameter.findChildren(recursive=False)[2].getText() == '[REQUIRED]':
            parameter_required = True
        else:
            parameter_required = False
    except IndexError:
        parameter_required = False
    except Exception as e:
        print(e)
        parameter_required = False

    if not parameter_type:
        parameter_type = 'Not defined'
        
    nested_lists = check_nested_lists(parameter)
    if nested_lists:
        # print(f"{parameter_name} ({parameter_type}) has {len(nested_lists)} nested lists")
        variables_output = parse_nested_lists(nested_lists)
        output = {
            "Name": parameter_name,
            "Description": parameter_description,
            "Type": parameter_type,
            "Required": parameter_required,
            f"{parameter_type} variables": variables_output
        }
        # print(f"Finished parsing nested_lists for {parameter_name} ({parameter_type}), and obtained the following output:")
        # print(output)
        return output
                # The string contains more parameters

    #if parameter_type == 'string' or parameter_type == 'integer' or parameter_type == 'boolean' or parameter_type == 'datetime' or parameter_type == 'bytes':
    else:
        return {
            "Name": parameter_name,
            "Description": parameter_description,
            "Type": parameter_type,
            "Required": parameter_required
        }

def check_nested_lists(parameter):
    if parameter.findChildren('ul',recursive=False):
        return parameter.findChildren('ul',recursive=False)
    else:
        return False

def parse_nested_lists(nested_lists):
    nested_lists_output = []
    for nested_list in nested_lists:
        nested_parameters=nested_list.findChildren('li',recursive=False)
        if nested_parameters:
            nested_parameters_output = {}
            for nested_parameter in nested_parameters:
                # nested_parameter_contents = ''.join([x.getText() for x in nested_parameter.contents])
                # if '(63 octets)' in nested_parameter_contents or '@subdomain.example.com' in nested_parameter_contents or '@example.com' in nested_parameter_contents:
                #     # Stupid list in https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.request_certificate (SAN parameter)
                #     # email list in https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html
                #     continue    
                if not test_if_valid_parameter(nested_parameter):
                    continue
                nested_parameter_output = parse_parameter(nested_parameter)
                nested_parameter_name = nested_parameter_output['Name']
                del nested_parameter_output['Name']
                nested_parameters_output[nested_parameter_name] = nested_parameter_output
        nested_lists_output.append(nested_parameters_output)
    if len(nested_lists) == 1:
        return nested_lists_output[0]
    else:
        return nested_lists_output

def test_if_valid_parameter(parameter):
    try: 
        # Generic check for the above issues (where there are nested lists with examples, instead of parameters)
        True
    except TypeError:
        return False

def save_data(filename,data):
    # Make output dir if it doesnt exist
    output_dir = pathlib.Path(__file__).parent.absolute() / 'output'
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    # print(f"Saving data to {filename}")
    with filepath.open("w") as write_file:
        json.dump(data, write_file, indent=4)



output_file = "something.txt"
try:
    os.remove(output_file)
except:
    pass


requests_session = requests.Session()
# url = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html'
# parse_service(url)

baseUrl = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/'
page = requests_session.get('https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/index.html')
soup = BeautifulSoup(page.content, 'html.parser')
list_of_services = soup.find_all("ul", class_="current")[0].findChild()

services = list_of_services.find_all('li')
total_services = len(services)
print(f"Found {total_services} services to parse")

for count,soup_tag in enumerate(services, start=1):
    service_url = baseUrl + soup_tag.find('a').attrs['href']
    service_name = soup_tag.getText()
    filename = service_name + '.json'
    print(f"[{count}/{total_services}] Parsing {service_url}")
    service_output = parse_service(service_url)
    save_data(filename,service_output)

