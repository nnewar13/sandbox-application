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

# Return job search response
def job_diva_response(data):
    """
        :params data: job result containing all the informations
        :return json: returns the custom response from the search results
        :return type: json
    """
    return  {
        'job_description': data.get('job description', ''),
        'job_status': data.get('job status', ''),
        'job_title': data.get('job title', ''),
        'job_type': data.get('job type', ''),
        'job_state': data.get('state', ''),
        'job_city': data.get('city', ''),
        'job_zipcode': data.get('zipcode', ''),
        'job_reference': data.get('reference #', ''),
        'job_start_date': data.get('start date', ''),
        'job_url': f"https://www1.jobdiva.com/portal/?a=7mjdnwzqdc2ko9b1vcs3bgnxd300120ade7c25nmm1ebcc1nttljjbqucdc35ubz&compid=-1#/jobs/{data.get('id', '')}"
    }

# Send the API Call
def job_diva_send_request(payload):
    # Add the authorization token and send the request
    secrets_manager = json.loads(get_secret(os.environ.get('JOBDIVA_SECRET_NAME'), os.environ.get('REGION')))
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {secrets_manager.get('access_token')}'
    }
    url = os.environ.get('JOBDIVA_URL') + '/apiv2/jobdiva/SearchJob'
    response = requests.post(url, headers=headers, json=payload)

    # raise exception when the status code is different than 200
    response.raise_for_status()
    
    # handle the search results and return the response
    logger.info(f'Search result received.')
    result = []
    response = response.json()
    for res in response:
        result.append(job_diva_response(res))
    return {
        'statusCode': 200,
        'body': json.dumps({'results': result})
    }


# Lambda Handler: loads the payload, sends the request to JobDiva and returns the response.
def lambda_handler(event, context):
    """
        Function to call the JobDiva API and fetch the search results
        :params event: event parameter that contains the information about the request
        :return response: three types of response possible - search results, failure from the JobDiva API or Internal Lambda Failure
        :return type: application/json
    """
    try:
        # create the request payload by adding the max return value and offset for pagination
        request_payload = json.loads(event['body'])
        offset = 0
        if request_payload['page']:
            offset = request_payload['page']
        request_payload["maxReturned"] = 25
        request_payload["offset"] = offset
        logger.info(f'Created the payload for the request. Payload: {request_payload}')

        # store the success response
        response = job_diva_send_request(request_payload)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logger.info('The refresh token failed to authenticate. Getting a new token using credentials.')
            refresh_token()
            response = job_diva_send_request(request_payload)
        else:
            response = {
                'statusCode': e.response.status_code,
                'body': json.dumps({'message': {e.response.json()}})
            }
    except Exception as error:
        logger.error(f"Error Occurred: {error}")
        response = {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error occurred while fetching the jobs information.'})
        }
    finally:
        # return the final response
        return response

def refresh_token():
    try:
        lambda_client = boto3.client('lambda', region_name = os.environ.get("REGION"))
        payload = {'SecretId': os.getenv.get('JOBDIVA_SECRET_ARN')}
        response = lambda_client.invoke(
            FunctionName = os.getenv.get('JOBDIVA_KEY_ROTATION_LAMBDA'),
            InvocationType = 'RequestResponse',
            Payload=json.dumps(payload).encode('utf-8')
        )
        if response['StatusCode'] != 200:
            logger.error(f"Error occurred while refreshing the token. Please check the lambda that rotates the key.")
            return {
                'statusCode': 500,
                'body': json.dumps({'message': 'Error occurred while fetching the jobs information.'})
            }
    except requests.exceptions.HTTPError as e:
        logger.error('The refresh token failed to authenticate. Getting a new token using credentials.')
        return {
            'statusCode': e.response.status_code,
            'body': json.dumps({'message': {e.response.json()}})
        }
    except Exception as error:
        logger.error(f"Error occurred while updating the refresh token. Error: {error}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error occurred while refreshing the token.'})
        }