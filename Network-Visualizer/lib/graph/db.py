import datetime
import os
import re
import shutil
import subprocess
import sys
import time
import warnings

from neo4j import GraphDatabase, exceptions
# from ingestor import enis,subnets,vpcs
# from lib.graph.nodes import Generic, Resource
# warnings.filterwarnings("ignore", category=ExperimentalWarning)

NEO4J_DB_DIR = "/data/databases"
NEO4J_ZIP_DIR = "/opt/awspx/data"
NEO4J_CONF_DIR = "/var/lib/neo4j/conf"
NEO4J_TRANS_DIR = "/data/transactions"


class Neo4j(object):

    driver = None

    def __init__(self,
                 host="localhost",
                 port="7691",
                 username="neo4j",
                 password=str(os.environ['NEO4J_AUTH'][6:]
                              if 'NEO4J_AUTH' in os.environ else "password"),
                 console=None):

        self.uri = f"bolt://{host}:{port}"
        self.username = username
        self.password = password

    def _run(self, tx, cypher):
        results = tx.run(cypher)
        return results

    def open(self):

        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.username, self.password),
            encrypted=False
        )

    def close(self):
        if self.driver is not None:
            self.driver.close()
            self.driver = None

    def available(self):
        try:
            self.open()
            self.driver.verify_connectivity()
        except Exception as e:
            print(e)
            return False
        return True

    def run(self, cypher):

        results = []

        if not self.available():
            print('Panic')

        try:
            with self.driver.session() as session:
                results = session.run(cypher).data()

        except exceptions.CypherSyntaxError as e:
            self.console.error(str(e))

        return results

neo4j = Neo4j()
neo4j.available()
# def create_person(tx, name):
#     tx.run("CREATE (a:Person {name: $name})", name=name)

# def create_friend_of(tx, name, friend):
#     tx.run("MATCH (a:Person) WHERE a.name = $name "
#            "CREATE (a)-[:KNOWS]->(:Person {name: $friend})",
#            name=name, friend=friend)

# with neo4j.driver.session() as session:
#     session.write_transaction(create_person, "Alice")
#     session.write_transaction(create_friend_of, "Alice", "Bob")
#     session.write_transaction(create_friend_of, "Alice", "Carl")

# print(enis[0])

# def create_eni_node(tx,node_data):
#     pass

