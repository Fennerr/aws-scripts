import boto3
import argparse
import json
import logging
import pathlib
from rich import print
# ###################################################
# # Input Variables
# parser = argparse.ArgumentParser()
# optionalNamed = parser.add_argument_group('optional named arguments')
# optionalNamed.add_argument("-p","--profile",default='default',type=str,help="The AWS profile to use")
# optionalNamed.add_argument("--env",type=str,help="Use Environment Variables rather than an AWS profile")
# optionalNamed.add_argument("--region",type=str,help="To enumerate the policies for a specific region (defaults to all regions)")
# optionalNamed.add_argument("--log",default='info',type=str,help="The logging level (debug,info,warning,error,critical)")

# # Get the passed arguements
# args = parser.parse_args()

class argss:
    profile = '981710073011_SSOPentestRole'
    # profile = '002627273584_SSOPentestRole'

args = argss()
# args["profile"] = "981710073011_SSOPentestRole"
s = boto3.session.Session(profile_name=args.profile,region_name='af-south-1')
ec2 = s.client("ec2",region_name='af-south-1')


########################### ENIS
class ENI(dict):
    # attributes_to_load = "Attachment","SubnetId","Groups"

    def __init__(self, eni_dict: dict) -> None:
        for k,v in eni_dict.items():
            # if k in ENI.attributes_to_load:
                self[k] = v
 
class ENIS(dict):
    def __init__(self,list_of_eni_dicts) -> None:
        for eni_dict in list_of_eni_dicts:
            network_id = eni_dict["NetworkInterfaceId"]
            self[network_id] = ENI(eni_dict)

    def attach_resource(self, eni_id: str, resource_type: str,resource_data: dict):
        if "attached_resource_types" not in self[eni_id].keys():
            self[eni_id]["attached_resource_types"] = [resource_type]
        elif resource_type not in self[eni_id]["attached_resource_types"]:
            self[eni_id]["attached_resource_types"].append(resource_type)
        # Can be attached to multiple eni's. Instanctiate the list if it's the first entry, else append to it
        if "attached_resources" not in self[eni_id].keys():
            self[eni_id]["attached_resources"] = [resource_data]
        elif resource_data not in self[eni_id]["attached_resources"]:
            self[eni_id]["attached_resources"].append(resource_data)

eni_data = ec2.describe_network_interfaces()["NetworkInterfaces"]
enis = ENIS(eni_data)

########################### Subnets
class SUBNET(dict):
    # attributes_to_load = "Attachment","SubnetId","Groups"
    def __init__(self, subnet_dict: dict) -> None:
        for k,v in subnet_dict.items():
            # if k in ENI.attributes_to_load:
            self[k] = v
        self.find_enis_in_subnet()
        # print(f"Found {len(self.enis_in_sunet)} ENIs in {self['SubnetId']}")

    def find_enis_in_subnet(self):
        self.enis_in_sunet = [([x['NetworkInterfaceId'],x['PrivateIpAddress']]) 
                    for k,x in enis.items() 
                    if x["SubnetId"] == self["SubnetId"]]
subnet_data = ec2.describe_subnets()["Subnets"]
subnets = [SUBNET(x) for x in subnet_data]
                    
# print(f"Total subnets: {len(subnets)}")

# for subnet in subnets:
#     # print(subnet['SubnetId'])
#     enis_in_subnet = [', '.join([x['NetworkInterfaceId'],x['PrivateIpAddress']]) 
#                     for k,x in enis.items() 
#                     if x["SubnetId"] == subnet["SubnetId"]]
    # print(f"ENIs in subnet {subnet['SubnetId']} ({subnet['CidrBlock']})")
    # print(enis_in_subnet)

########################### VPC
class VPC(dict):
    def __init__(self, vpc_dict: dict) -> None:
        for k,v in vpc_dict.items():
            # if k in ENI.attributes_to_load:
                self[k] = v
        self.find_subnets()
        # print(f"Found {len(self.subnets)} subnets in {self['VpcId']}")
        # print(self.subnets)
        self["AssociatedCidrBlocks"] = [x['CidrBlock'] for x in self['CidrBlockAssociationSet'] if x['CidrBlockState']['State'] == 'associated']

    def find_subnets(self):
        self.subnets = [{"SubnetId": x['SubnetId'],"CidrBlock":x['CidrBlock']}
                    for x in subnets 
                    if x["VpcId"] == self["VpcId"]]

vpc_data = ec2.describe_vpcs()["Vpcs"]
vpcs = [VPC(x) for x in vpc_data]
# for vpc in vpcs:
#     print(vpc['VpcId'])
#     subnets_in_vpc = [', '.join([x['SubnetId'],x['CidrBlock']]) 
#                     for x in subnets 
#                     if x["VpcId"] == vpc["VpcId"]]
#     print(subnets_in_vpc)

# for eni in enis:
#     # check if it is associated with EC2
#     # check if it is associated with ELB
#     # check if it is associated with RDS
#     # VPCE, EFS, TGW, Route53 Resolver,
#     pass

# Going to do it the other way around
# Parse each service, and then mark the ENIs with types when they come up

########################### EC2s
reservations = ec2.describe_instances()['Reservations']
ec2_instances = [y for x in reservations for y in x['Instances'] ]

for ec2_instance in ec2_instances:
    for network_interface in ec2_instance['NetworkInterfaces']:
        enis.attach_resource(eni_id = network_interface["NetworkInterfaceId"], resource_type='EC2', resource_data=network_interface)

########################### ELBs
elb_client = s.client("elb")
elbv2 =  s.client("elbv2")

for elbs in [elb_client.describe_load_balancers()["LoadBalancerDescriptions"], elbv2.describe_load_balancers()["LoadBalancers"]]:
    for elb in elbs:
        attached_enis = [v["NetworkInterfaceId"] for k,v in enis.items() if elb["LoadBalancerName"] in v["Description"]]
        for attached_eni in attached_enis:
            enis.attach_resource(eni_id = attached_eni, resource_type='ELB', resource_data=elb)

vpces = ec2.describe_vpc_endpoints()['VpcEndpoints']
for vpce in vpces:
    attached_enis = [x for x in enis if x in vpce["NetworkInterfaceIds"]]
    # print(attached_enis)
    for attached_eni in attached_enis:
            enis.attach_resource(eni_id = attached_eni, resource_type='VPCE', resource_data=vpce)

# Each transit gateway attachment has an ENI
tgws = ec2.describe_transit_gateway_vpc_attachments()['TransitGatewayVpcAttachments']
for twg in tgws:
    attach_id = twg['TransitGatewayAttachmentId']
    search_string = f'Network Interface for Transit Gateway Attachment {attach_id}'
    attached_enis = [k for k,v in enis.items() if search_string == v['Description']]
    for attached_eni in attached_enis:
            enis.attach_resource(eni_id = attached_eni, resource_type='TWG', resource_data=twg)
# print(tgws)

for ngw in ec2.describe_nat_gateways()['NatGateways']:
    for address in ngw['NatGatewayAddresses']:
        enis.attach_resource(eni_id = address['NetworkInterfaceId'], resource_type='NGW', resource_data={"NAT Gateway":ngw,"IP Addresses":address})

r53 = s.client('route53resolver')
resolvers = r53.list_resolver_endpoints()['ResolverEndpoints']
# print(len(resolvers))
for resolver in resolvers:
    resolver_id = resolver['Id']
    resolver_endpoints = r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=resolver_id)['IpAddresses']
    for endpoint in resolver_endpoints:
        endpoint_id = endpoint["IpId"]
        search_string = f"Route 53 Resolver: {resolver_id}:{endpoint_id}"
        attached_enis = [k for k,v in enis.items() if search_string == v['Description']]
        # print(f"Found attached enis: {[name for name in attached_enis]}")
        for attached_eni in attached_enis:
            enis.attach_resource(eni_id = attached_eni, resource_type='R53', resource_data={"Resolver Endpoint":resolver,"IP Addresses":endpoint})

efs = s.client("efs",region_name='af-south-1')
file_systems = efs.describe_file_systems()['FileSystems']

efs = s.client("efs",region_name='af-south-1')
file_systems = efs.describe_file_systems()['FileSystems']

for file_system in file_systems:
    file_system_id = file_system['FileSystemId']
    # SecurityAudit doesnt have perms to do efs.describe_access_points() - so I can't get the fsmt value to build the full search_string
    # Can still build the begining of the description - which will match all mount points for this efs
    search_string = f"EFS mount target for {file_system_id}"
    attached_enis = [k for k,v in enis.items() if search_string in v['Description']]
    for attached_eni in attached_enis:
        enis.attach_resource(eni_id = attached_eni, resource_type='EFS', resource_data=file_system)
#efs.describe_access_points()

sgs = ec2.describe_security_groups()['SecurityGroups']