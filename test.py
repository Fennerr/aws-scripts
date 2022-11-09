# Import the utils library by modifying sys.path and then importing 'util'
# import sys, pathlib
# library_path = pathlib.Path(__file__).absolute().parent.parent / 'lib'
# sys.path.append( str(library_path))
import lib.util
from lib.util.rich_console import console
from lib.util.args import args, parser
from lib.util.logging import logger
from lib.util.aws import sts_info, s
print('done')
# Add additional parameters
optionalNamed = parser.add_argument_group('To check a specific user or role')
optionalNamed.add_argument("--user",type=str,help="The user name to check")
optionalNamed.add_argument("--role",type=str,help="The role name to check")

# Get the args again
args = parser.parse_args()


# Setup the principal dict
principal = {}
if not (args.user or args.role):
    if 'assumed-role' in sts_info.get('Arn'):
        principal['type'] = 'Role'
        principal['name'] = sts_info.get('Arn').split('/')[-2]
    else:
        principal['type'] = 'User'
        principal['name'] = sts_info.get('Arn').split('/')[-1]
elif args.user:
    principal['type'] = 'User'
    principal['name'] =  args.user
elif args.role:
    principal['type'] = 'Role'
    principal['name'] =  args.role

print(f"IAM {principal['type']} Name: {principal['name'] }")

###################################################
# Check for permissions for the principal
iam = s.client('iam')

# Group logic
if principal['type'] == 'User':
    # print(sep)
    logger.info("Enumerating IAM Groups...")
    # Enumerate group memberships, and thier policies
    try:
        roles = iam.list_roles().get('Roles')
    except iam.exceptions.ClientError as e:
        logger.critical(f"{e}")
        logger.critical(f"Cannot determine group membership, exiting...")
        exit()

for role in console.tasklist(
    "Adding Transitive relationships",
    iterables=roles,
    done="Added Transitive relationships",
):
    print(role)