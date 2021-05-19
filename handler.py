import base64
import boto3
from botocore.exceptions import ClientError
import json
import logging
import os
import requests
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def cloudability(event, context):
    ''' Entry Point '''
    logger.info('## ENVIRONMENT VARIABLES')
    logger.info(os.environ)
    logger.info('## EVENT')
    logger.info(event)

    sm = boto3.client('secretsmanager')

    # Gather Secrets required to call Cloudability API
    try:
        cloudabilitySecret = sm.get_secret_value(
            SecretId=os.environ['smSecret'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.critical("The requested secret {0} was not found".format(
                os.environ['smSecret']))
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.critical("The request was invalid due to: {0}".format(e))
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.critical("The request had invalid params: {0}".format(e))
        else:
            logger.critical("Unexpected error: {0}".format(e))
        raise Exception()

    # Convert JSON to DICT
    cloudabilitySecretJSON = json.loads(cloudabilitySecret['SecretString'])

    # Check if correct values are in secret
    if 'apikey' in cloudabilitySecretJSON:
        cloudabilityAPIKey = cloudabilitySecretJSON['apikey']
    if 'accountid' in cloudabilitySecretJSON:
        cloudabilityAccountID = cloudabilitySecretJSON['accountid']
    if 'slackUrl' in cloudabilitySecretJSON:
        slackUrl = cloudabilitySecretJSON['slackUrl']

    cloudabilityAPIBase64 = base64.b64encode(
        (cloudabilityAPIKey + ":").encode("utf-8"))

    # Defining cloudability Post/Get information
    cloudabilityBaseUrl = 'https://api.cloudability.com/v3/vendors'
    cloudabilityAPIHeaders = {'Authorization': 'Basic ' +
                              cloudabilityAPIBase64.decode("utf-8")}

    # AWS Definitions
    roleName = os.environ['roleName']
    assumeRolePolicyTemplate = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::' + cloudabilityAccountID + \
        ':user/cloudability"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"%cloudabilityExternalId%"}}}]}'
    cloudabilityVerificationPolicy = '{"Version":"2012-10-17","Statement":{"Action":"iam:SimulatePrincipalPolicy","Resource":"arn:aws:iam::*:role/' + \
        roleName+'","Effect":"Allow","Sid":"VerifyRolePermissions"}}'
    cloudabilityMonitorResourcesPolicy = '{"Version":"2012-10-17","Statement":[{"Action":["cloudwatch:GetMetricStatistics","dynamodb:DescribeTable","dynamodb:ListTables","ec2:DescribeImages","ec2:DescribeInstances","ec2:DescribeRegions","ec2:DescribeReservedInstances","ec2:DescribeReservedInstancesModifications","ec2:DescribeSnapshots","ec2:DescribeVolumes","ec2:GetReservedInstancesExchangeQuote","ecs:DescribeClusters","ecs:DescribeContainerInstances","ecs:ListClusters","ecs:ListContainerInstances","elasticache:DescribeCacheClusters","elasticache:DescribeReservedCacheNodes","elasticache:ListTagsForResource","elasticmapreduce:DescribeCluster","elasticmapreduce:ListClusters","elasticmapreduce:ListInstances","rds:DescribeDBClusters","rds:DescribeDBInstances","rds:DescribeReservedDBInstances","rds:ListTagsForResource","redshift:DescribeClusters","redshift:DescribeReservedNodes","redshift:DescribeTags"],"Resource":"*","Effect":"Allow"}]}'

    def getAccountList():
        # This subroutine will retrieve all the account numbers in the organization
        accountlist = {}
        session = boto3.session.Session()
        try:
            client = session.client(
                service_name='organizations'
            )

            # Create a reusable Paginator
            paginator = client.get_paginator('list_accounts')

            # Create a PageIterator from the Paginator
            page_iterator = paginator.paginate(
                PaginationConfig={
                    'MaxItems': 100,
                    'PageSize': 20
                }
            )
        except Exception as e:
            logger.critical(
                "Unable to retrieve the accounts from the organization, with the error [{0}]".format(e))
            raise Exception()
        else:
            for Accounts in page_iterator:
                for Account in Accounts['Accounts']:
                    accountlist.update({Account['Id']: Account['Name']})
            return accountlist

    # Create in-line policies in the role for Cloudability
    def createInlinePolicy(accountIAM, policyName, policy):
        logger.info("Creating inline policy {0} for role {1}".format(
            policyName, roleName))

        # Checks if role exists, if not creates it.
        try:
            rolePolicy = accountIAM.get_role_policy(
                RoleName=roleName,
                PolicyName=policy
            )

        except ClientError as e:
            print(
                "Policy {0} does not exist, creating." .format(policyName))
            try:
                accountIAM.put_role_policy(
                    RoleName=roleName,
                    PolicyName=policyName,
                    PolicyDocument=policy
                )

                rolePolicy = accountIAM.get_role_policy(
                    RoleName=roleName,
                    PolicyName=policyName
                )
            except ClientError as e:
                print("Unexpected error: {0}".format(e))
                raise Exception()

        # Verifies if the policy defined in code matches the one in AWS. Corrects if not.
        if json.dumps(json.loads(policy)) == json.dumps(rolePolicy['PolicyDocument']):
            logging.debug(
                "{0} in role matches defined variable.".format(policyName))
        else:
            logger.warn("Discrepancy found in {0}.".format(policyName))
            logger.info("Current Policy: {0}".format(json.dumps(
                rolePolicy['PolicyDocument'])))
            logger.info("New Policy: {0}".format(json.dumps(
                json.loads(policy))))
            try:
                rolePolicy = accountIAM.put_role_policy(
                    RoleName=roleName,
                    PolicyName=policyName,
                    PolicyDocument=policy
                )
            except ClientError as e:
                print("Unexpected error: {0}".format(e))
                raise Exception()
        return True

    # Does API call to Cloudability, returns the response as JSON
    def cloudabilityAPICall(url, method='get', json={}):
        try:
            if method == 'post':
                if json == {}:
                    r = requests.post(url, headers=cloudabilityAPIHeaders)
                else:
                    r = requests.post(
                        url, headers=cloudabilityAPIHeaders, json=json)
            else:
                r = requests.get(url, headers=cloudabilityAPIHeaders)
            r.raise_for_status()
            logger.debug("requests.get to {0} successfull.".format(url))
        except requests.exceptions.HTTPError as err:
            logger.critical(err)
            raise Exception(err)
        logger.debug(r.json())
        return r.json()

    # Create IAM role required for Cloudability.
    def iamRoleCreation(cloudabilityExternalId, accountId, accountName):
        rootSts = boto3.client('sts')

        logger.debug('cloudabilityExternalId: {0}'.format(
            cloudabilityExternalId))
        logger.debug('accountId: {0}'.format(accountName))
        logger.debug('accountName: {0}'.format(accountName))

        assumeRolePolicy = assumeRolePolicyTemplate.replace(
            "%cloudabilityExternalId%", cloudabilityExternalId)

        logger.info("Trying assumeRole on account {0}".format(accountName))

        # Assumes role in target account
        try:
            accountCredsCall = rootSts.assume_role(
                RoleArn='arn:aws:iam::'+accountId+':role/AWSCloudFormationStackSetExecutionRole',
                RoleSessionName='CloudabilityRoleSet')
            accountCreds = accountCredsCall['Credentials']
        except ClientError as e:
            logger.critical("Unexpected error: {0}".format(e))
            raise Exception()

        accountIAM = boto3.client(
            'iam',
            aws_access_key_id=accountCreds['AccessKeyId'],
            aws_secret_access_key=accountCreds['SecretAccessKey'],
            aws_session_token=accountCreds['SessionToken'],)

        logger.debug("Getting role {0}".format(roleName))
        # Gets Role, if it can't find the role, creates role and kicks off policy creation.
        try:
            cloudabilityRole = accountIAM.get_role(
                RoleName=roleName
            )
        except ClientError as e:
            logger.info("Role roleName does not exist, creating.")
            try:
                cloudabilityRole = accountIAM.create_role(
                    RoleName=roleName,
                    AssumeRolePolicyDocument=assumeRolePolicy
                )
            except ClientError as e:
                logger.critical("Unexpected error: {0}".format(e))
                raise Exception()

        # Verifies if Assume Role Policy in code matches AWS. Corrects if not.
        if json.dumps(json.loads(assumeRolePolicy)) == json.dumps(cloudabilityRole['Role']['AssumeRolePolicyDocument']):
            logging.debug(
                "AssumeRolePolicyDocument in role matches defined variable.")
        else:
            logger.warn(
                "Discrepancy found in expected AssumeRolePolicyDocument.")
            logger.info("Current Policy: {0}".format(json.dumps(
                cloudabilityRole['Role']['AssumeRolePolicyDocument'])))
            logger.info("New Policy: {0}".format(json.dumps(
                json.loads(assumeRolePolicy))))
            try:
                cloudabilityRole = accountIAM.update_assume_role_policy(
                    RoleName=roleName,
                    PolicyDocument=assumeRolePolicy
                )
                logger.warn("Discrepancy corrected.")
            except ClientError as e:
                logger.critical("Unexpected error: {0}".format(e))
                raise Exception()

        # Creates the required policies.
        createInlinePolicy(
            accountIAM, "CloudabilityVerificationPolicy", cloudabilityVerificationPolicy)
        createInlinePolicy(accountIAM, "CloudabilityMonitorResourcesPolicy",
                           cloudabilityMonitorResourcesPolicy)

        # Required so it has time to get picked up by Cloudability at the verification step.
        time.sleep(10)

    # Triggers Cloudability to verify the cross account role and it's policies.
    def verifyCloudability(accountId, accountName):
        logger.info(
            "Trying to verify aws_role for account {0}".format(accountName))

        verifyurl = (cloudabilityBaseUrl + '/AWS/accounts/' +
                     accountId + '/verification')
        accountVerificationStatus = cloudabilityAPICall(
            verifyurl, 'post')

        if accountVerificationStatus['result']['verification']['state'] == "verified":
            logger.info(
                "Account {0} successfully verified with Cloudability".format(accountName))

        slackJson = {"text": "Account {0} successfully verified with Cloudability".format(accountName), "username": "Cloudability Automation",
                     "icon_emoji": ":cloud:"}

        # Send message to Slack of success.
        try:
            r = requests.post(slackUrl, json=slackJson)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.critical(err)
            raise Exception(err)

        else:
            logger.error(
                "Account {0} NOT verified with Cloudability".format(accountName))

    logger.debug(
        "Testing Cloudability API Connection via cloudabilityAPICall function")
    logger.debug(cloudabilityAPICall(
        cloudabilityBaseUrl))

    # Get account list
    accountList = getAccountList()
    for accountId, AccountName in accountList.items():
        logger.debug(
            "Getting Cloudability account info for account {0}".format(AccountName))

        checkurl = (cloudabilityBaseUrl + '/AWS/accounts/' + accountId)
        accountStatus = cloudabilityAPICall(checkurl)
        logger.debug(accountStatus)

        # Checks the different states an account can be in and starts different paths.
        if 'verification' in accountStatus['result'].keys():

            if accountStatus['result']['verification']['state'] == "verified":
                logger.info(
                    "Account {0} already verified.".format(AccountName))

            elif accountStatus['result']['verification']['state'] == "unverified":
                logger.warn(
                    "Account {0} in Cloudability but not verified.".format(AccountName))
                verifyCloudability(accountId, AccountName)
            elif accountStatus['result']['verification']['state'] == "error":
                logger.warn(
                    "Account {0} in Cloudability but in error state. Trying to fix roles and validate".format(AccountName))
                iamRoleCreation(
                    accountStatus['result']['authorization']['externalId'], accountId, AccountName)
                verifyCloudability(accountId, AccountName)

        else:
            logger.warn(
                "Account {0} not in Cloudability or not setup for aws_role authentication".format(AccountName))
            logger.info(
                "Creating aws_role authentication for account {0}".format(AccountName))

            accountUrl = (cloudabilityBaseUrl + '/AWS/accounts')
            jsonBody = {"vendorAccountId": accountId, "type": "aws_role"}

            accountCreation = cloudabilityAPICall(accountUrl, 'post', jsonBody)

            if 'authorization' in json.loads(json.dumps(accountCreation['result'])).keys():
                iamRoleCreation(
                    accountCreation['result']['authorization']['externalId'], accountId, AccountName)
                verifyCloudability(accountId, AccountName)
            else:
                logger.critical(
                    "Failed to create aws_role authentication for AWS account {0} in Cloudability.".format(AccountName))
                raise Exception()
