def lambda_handler(event, context):
    return {
        'statusCode': 200,
        'body': 'Lambda code created using terraform.'
    }