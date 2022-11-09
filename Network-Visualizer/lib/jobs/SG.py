import logging
from typing import Dict
from typing import List

import boto3
import neo4j
import json

from lib.cartography.util import aws_handle_regions
from lib.cartography.util import run_cleanup_job
from lib.cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_sg_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region)
    paginator = client.get_paginator('describe_security_groups')
    sgs: List[Dict] = []
    for page in paginator.paginate():
        sgs.extend(page['SecurityGroups'])
    return sgs


def _make_redshift_cluster_arn(region: str, aws_account_id: str, sg_identifier: str) -> str:
    """Cluster ARN format: https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-overview.html"""
    return f'arn:aws:ec2:{region}:{aws_account_id}:security-group/{sg_identifier}'

def transform_sg_data(sgs: List[Dict], region: str, current_aws_account_id: str) -> None:
    for sg in sgs:
        sg['arn'] = _make_redshift_cluster_arn(region, current_aws_account_id, eni["NetworkInterfaceId"])
        sg['ClusterCreateTime'] = str(sg['ClusterCreateTime']) if 'ClusterCreateTime' in sg else None


@timeit
def load_sg_data(
    neo4j_session: neo4j.Session, enis: List[Dict], region: str,
    current_aws_account_id: str, aws_update_tag: int,
) -> None:
    ingest_cluster = """
    MERGE (cluster:ENI{id: {Arn}})
    ON CREATE SET cluster.firstseen = timestamp(),
    cluster.arn = {Arn}
    SET cluster.availability_zone = {AZ},
    cluster.description = {Description},
    cluster.security_groups = {SecurityGroups},
    cluster.private_dns_name = {PrivateDnsName},
    cluster.private_ip_address = {PrivateIpAddress},
    cluster.status = {Status},
    cluster.subnet_id = {SubnetId},
    cluster.vpc_id = {VpcId},
    cluster.region = {Region}
    WITH cluster
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:RESOURCE]->(cluster)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """
    for eni in enis:
        neo4j_session.run(
            ingest_cluster,
            Arn=eni['arn'],
            AZ=eni['AvailabilityZone'],
            Description=eni['Description'],
            SecurityGroups=json.dumps(eni['Groups']),
            PrivateDnsName=eni['PrivateDnsName'],    # type: ignore
            PrivateIpAddress=eni['PrivateIpAddress'],    # type: ignore
            Status=eni['Status'],   # type: ignore
            SubnetId=eni['SubnetId'],
            VpcId=eni.get('VpcId'),
            Region=region,
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag,
        )
        # _attach_ec2_security_groups(neo4j_session, cluster, aws_update_tag)
        # _attach_iam_roles(neo4j_session, cluster, aws_update_tag)
        # _attach_aws_vpc(neo4j_session, cluster, aws_update_tag)




@timeit
def _attach_ec2_security_groups(neo4j_session: neo4j.Session, cluster: Dict, aws_update_tag: int) -> None:
    attach_cluster_to_group = """
    MATCH (c:RedshiftCluster{id:{ClusterArn}})
    MERGE (sg:EC2SecurityGroup{id:{GroupId}})
    MERGE (c)-[m:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
    ON CREATE SET m.firstseen = timestamp()
    SET m.lastupdated = {aws_update_tag}
    """
    for group in cluster.get('VpcSecurityGroups', []):
        neo4j_session.run(
            attach_cluster_to_group,
            ClusterArn=cluster['arn'],
            GroupId=group['VpcSecurityGroupId'],
            aws_update_tag=aws_update_tag,
        )


@timeit
def _attach_iam_roles(neo4j_session: neo4j.Session, cluster: Dict, aws_update_tag: int) -> None:
    attach_cluster_to_role = """
    MATCH (c:RedshiftCluster{id:{ClusterArn}})
    MERGE (p:AWSPrincipal{arn:{RoleArn}})
    MERGE (c)-[s:STS_ASSUMEROLE_ALLOW]->(p)
    ON CREATE SET s.firstseen = timestamp()
    SET s.lastupdated = {aws_update_tag}
    """
    for role in cluster.get('IamRoles', []):
        neo4j_session.run(
            attach_cluster_to_role,
            ClusterArn=cluster['arn'],
            RoleArn=role['IamRoleArn'],
            aws_update_tag=aws_update_tag,
        )


@timeit
def _attach_aws_vpc(neo4j_session: neo4j.Session, cluster: Dict, aws_update_tag: int) -> None:
    attach_cluster_to_vpc = """
    MATCH (c:RedshiftCluster{id:{ClusterArn}})
    MERGE (v:AWSVpc{id:{VpcId}})
    MERGE (c)-[m:MEMBER_OF_AWS_VPC]->(v)
    ON CREATE SET m.firstseen = timestamp()
    SET m.lastupdated = {aws_update_tag}
    """
    if cluster.get('VpcId'):
        neo4j_session.run(
            attach_cluster_to_vpc,
            ClusterArn=cluster['arn'],
            VpcId=cluster['VpcId'],
            aws_update_tag=aws_update_tag,
        )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_redshift_clusters_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_sgs(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, region: str,
    current_aws_account_id: str, aws_update_tag: int,
) -> None:
    data = get_sg_data(boto3_session, region)
    transform_sg_data(data, region, current_aws_account_id)
    load_sg_data(neo4j_session, data, region, current_aws_account_id, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing Redshift clusters for region '%s' in account '%s'.", region, current_aws_account_id)
        sync_redshift_clusters(neo4j_session, boto3_session, region, current_aws_account_id, update_tag)
    cleanup(neo4j_session, common_job_parameters)