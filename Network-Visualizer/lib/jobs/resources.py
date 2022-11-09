from typing import Dict

from . import apigateway
from . import config
from . import dynamodb
from . import ecr
from . import ecs
from . import eks
from . import elasticache
from . import elasticsearch
from . import emr
from . import iam
from . import kms
from . import lambda_function
from . import permission_relationships
from . import rds
from . import redshift
from . import resourcegroupstaggingapi
from . import route53
from . import s3
from . import secretsmanager
from . import securityhub
from . import sqs
from . import ssm
from .ec2.auto_scaling_groups import sync_ec2_auto_scaling_groups
from .ec2.elastic_ip_addresses import sync_elastic_ip_addresses
from .ec2.images import sync_ec2_images
from .ec2.instances import sync_ec2_instances
from .ec2.internet_gateways import sync_internet_gateways
from .ec2.key_pairs import sync_ec2_key_pairs
from .ec2.launch_templates import sync_ec2_launch_templates
from .ec2.load_balancer_v2s import sync_load_balancer_v2s
from .ec2.load_balancers import sync_load_balancers
from .ec2.nat_gateways import sync_nat_gateways
from .ec2.network_interfaces import sync_network_interfaces
from .ec2.reserved_instances import sync_ec2_reserved_instances
from .ec2.security_groups import sync_ec2_security_groupinfo
from .ec2.snapshots import sync_ebs_snapshots
from .ec2.subnets import sync_subnets
from .ec2.tgw import sync_transit_gateways
from .ec2.volumes import sync_ebs_volumes
from .ec2.vpc import sync_vpc
from .ec2.vpc_peerings import sync_vpc_peerings
from .ec2.network_firewall import sync_network_firewalls

RESOURCE_FUNCTIONS: Dict = {
    # 'iam': iam.sync,
    # 's3': s3.sync,
    # 'dynamodb': dynamodb.sync,
    # `ec2:instance` must be included before `ssm` and `ec2:images`,
    # they rely on EC2Instance data provided by this module.
    'ec2:instance': sync_ec2_instances,
    'ec2:load_balancer': sync_load_balancers,
    'ec2:load_balancer_v2': sync_load_balancer_v2s,
    'ec2:network_interface': sync_network_interfaces,
    'ec2:security_group': sync_ec2_security_groupinfo,
    'ec2:subnet': sync_subnets,
    'ec2:tgw': sync_transit_gateways,
    'ec2:vpc': sync_vpc,
    # 'ec2:vpc_peering': sync_vpc_peerings,
    'ec2:internet_gateway': sync_internet_gateways,
    'ec2:nat_gateway': sync_nat_gateways,
    'ec2:network_firewall': sync_network_firewalls
#     'ecr': ecr.sync,
#     'ecs': ecs.sync,
#     'eks': eks.sync,
#     'elasticache': elasticache.sync,
#     'elastic_ip_addresses': sync_elastic_ip_addresses,
#     'emr': emr.sync,
#     'lambda_function': lambda_function.sync,
#     'kms': kms.sync,
#     'rds': rds.sync,
#     'redshift': redshift.sync,
#     'elasticsearch': elasticsearch.sync,
#     'permission_relationships': permission_relationships.sync,
#     'resourcegroupstaggingapi': resourcegroupstaggingapi.sync,
#     'apigateway': apigateway.sync,
}