# import libraries
import json
import logging
import os
import boto3

# import libraries from Lambda Layer 
from secret_manager_helper import get_secret
import requests

# Setup Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global Variables for secrets manager and used when updating the token and refresh token
user_id = None,
user_name = None,
user_password = None,
access_token = None,
refresh_token = None,
string_id = None

# setup secrets manager
def secrets_manager_update():
    global user_id, user_name, user_password, access_token, refresh_token, string_id
    try:
        logger.info('Updating the credentials in the secrets manager.')
        client = boto3.client(
            service_name='secretsmanager',
            region_name=os.environ.get('REGION')
        )
        client.update_secret(
            KmsKeyId = os.environ.get('KMS'),
            Description = 'Rotating the access token and refresh token',
            SecretId = string_id,
            SecretString = json.dumps({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'clientid': user_id,
                'username': user_name,
                'password': user_password
            })
        )
        logger.info('Rotated the key successfully.')
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'token updated successfully.'
            })
        }
    except Exception as e:
        logger.info(f'Exception occurred while updating the token. Error: {e}')
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal error while fetching the records.'
            })
        }

def update_refresh_token(event, context):
    '''
        Function to fetch a new token using the refresh token
        :params event: input data that's passed to the function wehn it's invoked
        :params context: lamdba execution information
        :return response: status code with message
        :return type: json
    '''
    global access_token, refresh_token, user_id, user_name, user_password, string_id
    try:
        url = os.environ.get('JOBDIVA_URL') + '/apiv2/v2/refreshToken'
        secrets_manager = json.loads(get_secret(os.environ.get('JOBDIVA_SECRET_NAME'), os.environ.get('REGION')))
        user_id = secrets_manager.get('clientid')
        user_name = secrets_manager.get('username')
        user_password = secrets_manager.get('password')
        refresh_token = secrets_manager.get('refresh_token')
        string_id = os.environ.get('JOBDIVA_SECRET_ARN')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {refresh_token}'
        }
        logger.info('Created the request payload for the refresh token.')

        # send the request and raise error if not 200
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        # if success then return the success response
        logger.info('Token refreshed.')
        access_token = response.json().get('token')
        refresh_token = response.json().get('refreshtoken')
        response = secrets_manager_update()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logger.info('The refresh token failed to authenticate. Getting a new token using credentials.')
            response = get_new_token()
        else:
            logger.info(f'The refresh token failed at the Job Diva endpoint. Error: {e}')
            response = {
                'statusCode': response.status_code,
                'body': json.dumps(
                    {
                        'error': {
                            'message': response.json(),
                            'status': response.status_code
                        }
                    }
                ),
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            }
    except Exception as error:
        logger.info(f'Error occurred in lambda execution: {error}')
        response = {
            'statusCode': 500,
            'body': json.dumps('Internal server error.'),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }
    finally:
        # returning the final response
        return response


def get_new_token():
    global access_token, refresh_token, user_id, user_name, user_password
    try:
        secrets_manager = json.loads(get_secret(os.environ.get('JOBDIVA_SECRET_NAME'), os.environ.get('REGION')))
        url = os.environ.get('JOBDIVA_URL') + '/apiv2/v2/authenticate'
        user_id = secrets_manager.get('clientid')
        user_name = secrets_manager.get('username')
        user_password = secrets_manager.get('password')
        headers = {
            'Content-Type': 'application/json'
        }
        params = f"clientid={user_id}&username={user_name}&password={user_password}"
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        access_token = response.json().get('token')
        refresh_token = response.json().get('refreshtoken')
        return secrets_manager_update()
    except Exception as e:
        logger.info(f'Exception occurred while getting the new token and refresh token. Error: {e}')
        return {
            'statusCode': response.status_code,
            'body': json.dumps(
                {
                    'error': {
                        'message': response.json(),
                        'status': response.status_code
                    }
                }
            ),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }