import logging
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
def get_nat_gateways(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    return client.describe_nat_gateways()['NatGateways']


@timeit
def load_nat_gateways(
    neo4j_session: neo4j.Session, nat_gateways: List[Dict], region: str,
    current_aws_account_id: str, update_tag: int,
) -> None:
    logger.info("Loading %d NAT Gateways in %s.", len(nat_gateways), region)
    # TODO: Right now this won't work in non-AWS commercial (GovCloud, China) as partition is hardcoded
    query = """
    UNWIND {nat_gateways} as ngw
        MERGE (ng:AWSNatGateway{id: ngw.NatGatewayId})
        ON CREATE SET
            ng.firstseen = timestamp(),
            ng.region = {region}
        SET
            ng.lastupdated = {aws_update_tag},
            ng.state = ngw.State,
            ng.connectivity_type = ngw.ConnectivityType,
            ng.subnet_id = ngw.SubnetId,
            ng.vpc_id = ngw.VpcId,
            ng.arn = "arn:aws:ec2:"+{region}+":"+{current_aws_account_id}+":natgateway/"+ngw.NatGatewayId
        WITH ngw, ng

        MATCH (awsAccount:AWSAccount {id: {aws_account_id}})
        MERGE (awsAccount)-[r:RESOURCE]->(ng)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = {aws_update_tag}
        WITH ngw, ng

        UNWIND ngw.NatGatewayAddresses as address
        MATCH (netinf:NetworkInterface{id: address.NetworkInterfaceId})
        MERGE (ng)-[r:ATTACHED_TO]->(netinf)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = {aws_update_tag}
    """

    neo4j_session.run(
        query,
        nat_gateways=nat_gateways,
        region=region,
        aws_account_id=current_aws_account_id,
        aws_update_tag=update_tag,
        current_aws_account_id=current_aws_account_id,
    ).consume()


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    logger.debug("Running Internet Gateway cleanup job.")
    run_cleanup_job('aws_import_internet_gateways_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_nat_gateways(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing NAT Gateways for region '%s' in account '%s'.", region, current_aws_account_id)
        nat_gateways = get_nat_gateways(boto3_session, region)
        load_nat_gateways(neo4j_session, nat_gateways, region, current_aws_account_id, update_tag)

    cleanup(neo4j_session, common_job_parameters)
