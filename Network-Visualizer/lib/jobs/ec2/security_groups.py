import logging
from string import Template
from typing import Dict
from typing import List

import boto3
import neo4j

from .util import get_botocore_config
from lib.cartography.util import aws_handle_regions
from lib.cartography.util import run_cleanup_job
from lib.cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_ec2_security_group_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_security_groups')
    security_groups: List[Dict] = []
    for page in paginator.paginate():
        security_groups.extend(page['SecurityGroups'])
    return security_groups

@timeit
@aws_handle_regions
def get_network_interface_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_network_interfaces')
    enis: List[Dict] = []
    for page in paginator.paginate():
        enis.extend(page['NetworkInterfaces'])
    return enis

@timeit
@aws_handle_regions
def get_subnet_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_subnets')
    subnets: List[Dict] = []
    for page in paginator.paginate():
        subnets.extend(page['Subnets'])
    return subnets

@timeit
def load_ec2_security_group_rule(neo4j_session: neo4j.Session, group: Dict, rule_type: str, update_tag: int) -> None:
    INGEST_RULE_TEMPLATE = Template("""
    MERGE (rule:$rule_label{ruleid: {RuleId}})
    ON CREATE SET rule :IpRule, rule.firstseen = timestamp(), rule.fromport = {FromPort}, rule.toport = {ToPort},
    rule.protocol = {Protocol}
    SET rule.lastupdated = {update_tag}
    WITH rule
    MATCH (group:EC2SecurityGroup{groupid: {GroupId}})
    MERGE (group)<-[r:MEMBER_OF_EC2_SECURITY_GROUP]-(rule)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag};
    """)

    ingest_rule_group_pair = """
    MERGE (group:EC2SecurityGroup{id: {GroupId}})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = {GroupId}
    SET group.lastupdated = {update_tag}
    WITH group
    MATCH (inbound:IpRule{ruleid: {RuleId}})
    MERGE (inbound)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    ingest_range = """
    MERGE (range:IpRange{id: {RangeId}})
    ON CREATE SET range.firstseen = timestamp(), range.range = {RangeId}
    SET range.lastupdated = {update_tag}
    WITH range
    MATCH (rule:IpRule{ruleid: {RuleId}})
    MERGE (rule)<-[r:MEMBER_OF_IP_RULE]-(range)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    group_id = group["GroupId"]
    rule_type_map = {"IpPermissions": "IpPermissionInbound", "IpPermissionsEgress": "IpPermissionEgress"}

    if group.get(rule_type):
        for rule in group[rule_type]:
            protocol = rule.get("IpProtocol", "all")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            ruleid = f"{group_id}/{rule_type}/{from_port}{to_port}{protocol}"
            # NOTE Cypher query syntax is incompatible with Python string formatting, so we have to do this awkward
            # NOTE manual formatting instead.
            neo4j_session.run(
                INGEST_RULE_TEMPLATE.safe_substitute(rule_label=rule_type_map[rule_type]),
                RuleId=ruleid,
                FromPort=from_port,
                ToPort=to_port,
                Protocol=protocol,
                GroupId=group_id,
                update_tag=update_tag,
            )

            neo4j_session.run(
                ingest_rule_group_pair,
                GroupId=group_id,
                RuleId=ruleid,
                update_tag=update_tag,
            )

            for ip_range in rule["IpRanges"]:
                range_id = ip_range["CidrIp"]
                neo4j_session.run(
                    ingest_range,
                    RangeId=range_id,
                    RuleId=ruleid,
                    update_tag=update_tag,
                )


@timeit
def load_ec2_security_groupinfo(
    neo4j_session: neo4j.Session, data: List[Dict], region: str,
    current_aws_account_id: str, update_tag: int,
) -> None:
    ingest_security_group = """
    MERGE (group:EC2SecurityGroup{id: {GroupId}})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = {GroupId}
    SET group.name = {GroupName}, group.description = {Description}, group.region = {Region},
    group.lastupdated = {update_tag}

    WITH group
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:RESOURCE]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    
    WITH group
    MATCH (vpc:AWSVpc{id: {VpcId}})
    MERGE (vpc)-[rg:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET rg.firstseen = timestamp()
    """

    for group in data:
        group_id = group["GroupId"]

        neo4j_session.run(
            ingest_security_group,
            GroupId=group_id,
            GroupName=group.get("GroupName"),
            Description=group.get("Description"),
            VpcId=group.get("VpcId", None),
            Region=region,
            AWS_ACCOUNT_ID=current_aws_account_id,
            update_tag=update_tag,
        )

        load_ec2_security_group_rule(neo4j_session, group, "IpPermissions", update_tag)
        load_ec2_security_group_rule(neo4j_session, group, "IpPermissionsEgress", update_tag)


@timeit
def cleanup_ec2_security_groupinfo(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job(
        'aws_import_ec2_security_groupinfo_cleanup.json',
        neo4j_session,
        common_job_parameters,
    )


@timeit
def sync_ec2_security_groupinfo(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing EC2 security groups for region '%s' in account '%s'.", region, current_aws_account_id)
        sg_data = get_ec2_security_group_data(boto3_session, region)
        eni_data = get_network_interface_data(boto3_session, region)
        subnet_data = get_subnet_data(boto3_session, region)
        something(boto3_session,sg_data,eni_data,subnet_data, neo4j_session, region, current_aws_account_id, update_tag)

        load_ec2_security_groupinfo(neo4j_session, sg_data, region, current_aws_account_id, update_tag)
    cleanup_ec2_security_groupinfo(neo4j_session, common_job_parameters)



@timeit
def load_network_interface_relations(
    neo4j_session: neo4j.Session, eni_associations: List[Dict], region: str,
    aws_account_id: str, update_tag: int,
) -> None:
    """
    Creates (:NetworkInterface)-[:CAN_ACCESS {protocol,from_port,to_port}]->(:NetworkInterface)
    """
    ingest_network_interface_relations = """
    WITH {eni_associations} as x
        UNWIND x.allowed_enis as allowed_eni
        UNWIND x.associated_enis as associated_eni
            match (eni:NetworkInterface{id:allowed_eni}), (eni2:NetworkInterface{id:associated_eni}) 
            MERGE (eni)-[r:CAN_ACCESS]->(eni2)
            ON CREATE SET r.firstseen = timestamp(),
                r.from_port = x.from_port,
                r.to_port = x.to_port,
                r.protocol = x.protocol,
                r.source = x.source
            SET r.lastupdated = {update_tag}
    """
    logger.info("Creating relationships showing that %d ENIs that can access %d ENIs (%s %s-%s) in %s.", len(eni_associations['allowed_enis']), len(eni_associations['associated_enis']), eni_associations['protocol'], eni_associations['from_port'], eni_associations['to_port'], region)
    neo4j_session.run(
        ingest_network_interface_relations, eni_associations=eni_associations,
        update_tag=update_tag, region=region, aws_account_id=aws_account_id,
    )


def something(boto3_session,sg_data,eni_data,subnet_data, neo4j_session, region, aws_account_id, update_tag):
    import ipaddress

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

    enis = ENIS(eni_data)

    import itertools
    ec2 = boto3_session.client('ec2')
    class SUBNET(dict):
        protocol_mapping = {
            '1': 'icmp',
            '6': 'tcp',
            '17': 'udp',
            '58': 'icmpv6'
        }
        # attributes_to_load = "Attachment","SubnetId","Groups"
        def __init__(self, subnet_dict: dict) -> None:
            for k,v in subnet_dict.items():
                # if k in ENI.attributes_to_load:
                self[k] = v
            self.find_enis_in_subnet()
            # print(f"Found {len(self['enis_in_sunet'])} ENIs in {self['SubnetId']}")
            self.get_nacls()
            # self.check_nacls()

        def find_enis_in_subnet(self):
            self['enis_in_sunet'] = [k 
                        for k,x in enis.items() 
                        if x["SubnetId"] == self["SubnetId"]]

        def get_nacls(self):
            self['nacls'] = ec2.describe_network_acls(Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [
                        self['SubnetId']
                    ]
                }
            ])['NetworkAcls']

        def to_ranges(self,iterable):
            iterable = sorted(set(iterable))
            for key, group in itertools.groupby(enumerate(iterable),
                                                lambda t: t[1] - t[0]):
                group = list(group)
                yield group[0][1], group[-1][1]

        def check_nacls(self,ip_address,protocol,from_port,to_port,ingress=True):
            output = {'Allowed':[],'NotAllowed':[]}
            test_port_range = range(int(from_port),int(to_port)+1)
            for nacl in self['nacls']:
                ingress_rules = sorted([entry for entry in nacl['Entries'] if entry['Egress'] == False], key=lambda d: d['RuleNumber'])
                egress_rules = sorted([entry for entry in nacl['Entries'] if entry['Egress'] == True], key=lambda d: d['RuleNumber'])
                if ingress:
                    target_rules = ingress_rules
                else:
                    target_rules = egress_rules

                for entry in target_rules:
                    overlapping_ports = []
                    not_overlapping_ports = []
                    if ipaddress.ip_address(ip_address) not in ipaddress.IPv4Network(entry['CidrBlock']):
                        continue
                    # Protocols for NACLs are always numeric (ie 6 for tcp)
                    # Protocols for SGs use common name if it's udp,tcp,icmp,icmpv6 
                    # Will convert to SG format
                    entry_protocol = SUBNET.protocol_mapping[entry['Protocol']] if entry['Protocol'] in SUBNET.protocol_mapping else entry['Protocol']
                    if entry_protocol != '-1' and entry_protocol != protocol:
                        continue
                    entry_from_port = entry['PortRange']['From'] if 'PortRange' in entry.keys() else 0
                    entry_to_port = entry['PortRange']['To'] if 'PortRange' in entry.keys() else 65535
                    entry_port_range = range(entry_from_port,entry_to_port+1)

                    overlapping_ports = [x for x in test_port_range if x in entry_port_range]
                    test_port_range = [x for x in test_port_range if x not in entry_port_range]

                    if not overlapping_ports:
                        continue

                    if entry['RuleAction'] == 'allow':
                        output['Allowed'].append({
                            'Ports': list(self.to_ranges(overlapping_ports)),
                            'RuleNumber': entry['RuleNumber']
                        })
                    else:
                        output['NotAllowed'].append({
                            'Ports': list(self.to_ranges(overlapping_ports)),
                            'RuleNumber': entry['RuleNumber'],
                            'Default': True if entry == ingress_rules[-1] else False
                        })
            return output

    subnets ={x['SubnetId']: SUBNET(x) for x in subnet_data}

    def parse_allowed_enis(allowed_enis,associated_enis,protocol,from_port,to_port):
        for allowed_eni in allowed_enis:
            for associated_eni in associated_enis:
                target_subnet = enis[associated_eni]['SubnetId']
                source_subnet = enis[allowed_eni]['SubnetId']
                if not source_subnet == target_subnet:
                    # Need to check the subnet NACL
                    target_ip = enis[associated_eni]['PrivateIpAddress']
                    source_ip = enis[allowed_eni]['PrivateIpAddress']
                    # Check Ingress rules for the target subnet
                    target_subnet_ingress_nacl_result = subnets[target_subnet].check_nacls(ip_address=source_ip,protocol=protocol,from_port=from_port,to_port=to_port)
                    # Check Egress rules for the source subnet
                    source_subnet_egress_nacl_result = subnets[source_subnet].check_nacls(ip_address=target_ip,protocol=protocol,from_port=from_port,to_port=to_port,ingress=False)
                    if len(source_subnet_egress_nacl_result['Allowed']) == 0 or len(target_subnet_ingress_nacl_result['Allowed']) == 0:
                        if allowed_eni in allowed_enis:
                            # print(f"Removing {allowed_eni} from the allowed_enis")
                            allowed_enis.remove(allowed_eni)
        return allowed_enis


    sg_eni_mapping = {}
    # Need to create these neo4j relationships
    for sg in sg_data:
        sg_eni_mapping[sg['GroupId']] = [k for k,eni in enis.items() if sg['GroupId'] in [attached_sg['GroupId'] for attached_sg in eni['Groups']]]

    for sg in sg_data:
        sg_id = sg['GroupId']
        sg_owner_id = sg['OwnerId']

        associated_enis = [k for k,eni in enis.items() if sg_id in [attached_sg['GroupId'] for attached_sg in eni['Groups']]]
        if not associated_enis:
            continue

        for ip_permission in sg['IpPermissions']:
            protocol = ip_permission['IpProtocol']
            if protocol == "-1" or protocol == "50":
                protocol = 'All'
                from_port = 0
                to_port = 65535
            else:
                from_port = ip_permission['FromPort'] if 'FromPort' in ip_permission.keys() else ''
                to_port = ip_permission['ToPort'] if 'ToPort' in ip_permission.keys() else ''

            ip_ranges = ip_permission['IpRanges']
            for ip_range in ip_ranges:
                cidr_range = ip_range['CidrIp']
                network = ipaddress.IPv4Network(cidr_range) 
                # TODO: Need to loop through each ENI's PrivateIpAddresses instead of just using the primary address
                allowed_enis = [k for k,eni in enis.items() if ipaddress.ip_address(eni['PrivateIpAddress']) in network and k not in associated_enis]
                if not allowed_enis or allowed_enis==associated_enis:
                    continue
                after_nacl_allowed_enis = parse_allowed_enis(allowed_enis,associated_enis,protocol,from_port,to_port)
                difference = len(allowed_enis)-len(after_nacl_allowed_enis)
                print(f'{sg_id} allows {len(after_nacl_allowed_enis)} ENIs to access {len(associated_enis)} ENIs ({protocol}: {from_port}-{to_port}) (CIDR Range {cidr_range})'  
                    f'({difference} ENIs prevented by Subnet NACL)' if difference else "" )
                eni_associations= {
                    'allowed_enis': after_nacl_allowed_enis,
                    'associated_enis': associated_enis,
                    'protocol': protocol,
                    'from_port': from_port,
                    'to_port': to_port,
                    'source': f'{sg_id} allows {cidr_range}'
                }
                load_network_interface_relations(neo4j_session=neo4j_session, eni_associations=eni_associations,region=region,aws_account_id=aws_account_id,update_tag=update_tag)

            referenced_sgs = ip_permission['UserIdGroupPairs']
            for referenced_sg in referenced_sgs:
                referenced_sg_id = referenced_sg['GroupId']
                if referenced_sg_id not in sg_eni_mapping.keys():
                    continue
                allowed_enis = [k for k,eni in enis.items() if referenced_sg_id in [attached_sg['GroupId'] for attached_sg in eni['Groups']] and k not in associated_enis]
                if not allowed_enis:
                    continue
                if not referenced_sg['UserId'] == sg_owner_id:
                    print(f"External SG referenced in {sg_id}!")
                after_nacl_allowed_enis = parse_allowed_enis(allowed_enis,associated_enis,protocol,from_port,to_port)
                difference = len(allowed_enis)-len(after_nacl_allowed_enis)
                print(f'{sg_id} allows {len(after_nacl_allowed_enis)} ENIs to access {len(associated_enis)} ENIs ({protocol}: {from_port}-{to_port}) (SG Reference {referenced_sg_id})'  
                    f'({difference} ENIs prevented by Subnet NACL)' if difference else "" )
                eni_associations= {
                    'allowed_enis': after_nacl_allowed_enis,
                    'associated_enis': associated_enis,
                    'protocol': protocol,
                    'from_port': from_port,
                    'to_port': to_port,
                    'source': f'{sg_id} allows {referenced_sg_id}'
                }
                load_network_interface_relations(neo4j_session=neo4j_session, eni_associations=eni_associations,region=region,aws_account_id=aws_account_id,update_tag=update_tag)