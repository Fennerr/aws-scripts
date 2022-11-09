import boto3
import time
import lib.jobs.ENI as ENI
import lib.jobs.SG as SG
from lib.graph.db import neo4j
from lib.cartography.config import Config
import lib.jobs
import logging

class argss:
    # profile = '981710073011_SSOPentestRole'
    # profile = '981710073011_SSOAdmUsrRole'
    profile = '002627273584_SSOAdmUsrRole'
    # profile = '002627273584_SSOPentestRole'

args = argss()
# args["profile"] = "981710073011_SSOPentestRole"
session = boto3.session.Session(profile_name=args.profile,region_name='af-south-1')

sts = session.client('sts')
current_account_id = sts.get_caller_identity()['Account']
aws_update_time = int(time.time())

config = Config(
    neo4j_uri='bolt://localhost:7691',
    neo4j_user='',
    neo4j_password=''
)

logging.basicConfig(level=logging.INFO)
lib.jobs.start_aws_ingestion(neo4j_session=neo4j.driver.session(),config=config,aws_profile_name=args.profile)

# SG.sync_sgs(neo4j.driver.session(),session,'af-south-1',current_account_id,aws_update_time)
# ENI.sync_enis(neo4j.driver.session(),session,'af-south-1',current_account_id,aws_update_time)

test =123 


