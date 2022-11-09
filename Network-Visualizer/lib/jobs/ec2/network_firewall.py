import logging
from typing import Dict
from typing import List

import boto3
import neo4j

from .util import get_botocore_config
from lib.cartography.util import aws_handle_regions
from lib.cartography.util import run_cleanup_job
from lib.cartography.util import timeit
from lib.jobs.ec2.network_interfaces import get_network_interface_data

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_network_firewalls(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('network-firewall', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('list_firewalls')
    network_firewalls: List[Dict] = []
    for page in paginator.paginate():
        network_firewalls.extend(page['Firewalls'])
    return network_firewalls

@timeit
@aws_handle_regions
def get_firewall_sync_states(boto3_session: boto3.session.Session, region: str, firewall_name: str) -> Dict:
    client = boto3_session.client('network-firewall', region_name=region)
    return client.describe_firewall(FirewallName=firewall_name)['FirewallStatus']['SyncStates']

@timeit
@aws_handle_regions
def get_firewall_associatations(boto3_session: boto3.session.Session, region: str, firewall_name: str, eni_data: List[Dict]) -> Dict:
    firewall_associations = []
    firewall_sync_states = get_firewall_sync_states(boto3_session, region, firewall_name)
    for az,data in firewall_sync_states.items():
        endpoint_id = data['Attachment']['EndpointId']
        firewall_associations.append([eni for eni in eni_data if endpoint_id in eni['Description']][0]['NetworkInterfaceId'])
    return firewall_associations

@timeit
def load_network_interface_network_firewall_relations(
    neo4j_session: neo4j.Session, firewall_name, firewall_associations: List, region: str, update_tag: int,
) -> None:
    """
    Creates (:AWSNetworkFirewall)-[:NETWORK_INTERFACE]->(:NetworkInterface)
    """
    ingest_network_interface_elb_relations = """
    UNWIND {firewall_associations} AS netinf_id
        MATCH (netinf:NetworkInterface{id: netinf_id}),
            (nf:AWSNetworkFirewall{id: $firewall_name})
        MERGE (nf)-[r:NETWORK_INTERFACE]->(netinf)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = {update_tag}
    """
    logger.debug("Attaching %d network interfaces to Network Firewall in %s.", len(firewall_associations), region)
    neo4j_session.run(
        ingest_network_interface_elb_relations, firewall_name=firewall_name, firewall_associations=firewall_associations,
        update_tag=update_tag, region=region,
    )

@timeit
def load_network_firewalls(
    neo4j_session: neo4j.Session, network_firewalls: List[Dict], region: str,
    current_aws_account_id: str, update_tag: int,
) -> None:
    logger.info("Loading %d Network Firewalls in %s.", len(network_firewalls), region)
    # TODO: Right now this won't work in non-AWS commercial (GovCloud, China) as partition is hardcoded
    query = """
    UNWIND {network_firewalls} as nfw
        MERGE (nf:AWSNetworkFirewall{id: nfw.FirewallName})
        ON CREATE SET
            nf.firstseen = timestamp(),
            nf.region = {region}
        SET
            nf.lastupdated = {aws_update_tag},
            nf.arn = nfw.FirewallArn
        WITH nfw, nf

        MATCH (awsAccount:AWSAccount {id: {aws_account_id}})
        MERGE (awsAccount)-[r:RESOURCE]->(nf)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = {aws_update_tag}
    """

    neo4j_session.run(
        query,
        network_firewalls=network_firewalls,
        region=region,
        aws_account_id=current_aws_account_id,
        aws_update_tag=update_tag,
        current_aws_account_id=current_aws_account_id,
    ).consume()


# @timeit
# def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
#     logger.debug("Network Firewalls cleanup job.")
#     run_cleanup_job('aws_import_internet_gateways_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_network_firewalls(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing Network Firewalls for region '%s' in account '%s'.", region, current_aws_account_id)
        network_firewalls = get_network_firewalls(boto3_session, region)
        if not len(network_firewalls):
            continue
        load_network_firewalls(neo4j_session, network_firewalls, region, current_aws_account_id, update_tag)

        eni_data = get_network_interface_data(boto3_session, region)
        for firewall in network_firewalls:
            firewall_name = firewall['FirewallName']
            firewall_associations = get_firewall_associatations(boto3_session,region,firewall_name,eni_data)
            load_network_interface_network_firewall_relations(neo4j_session,firewall_name,firewall_associations,region,update_tag)

    # cleanup(neo4j_session, common_job_parameters)
