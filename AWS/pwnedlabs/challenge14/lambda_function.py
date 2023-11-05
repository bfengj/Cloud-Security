import os
import json
import urllib.request
from datetime import datetime
import boto3
import uuid

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket_name = 'hl-status-log-bucket'
    
    try:
        target = event.get('target', 'http://huge-logistics.com')

        response = urllib.request.urlopen(target)
        data = response.read()
        return_status = 'Service is available.' if response.getcode() == 200 else 'Service is not available.'
        return {
            'statusCode': response.getcode(),
            'statusMessage': return_status,
            'body': data.decode('utf-8')
        }
    except urllib.error.HTTPError as e:
        return {
            'statusCode': e.code,
            'body': json.dumps({
                'message': 'HTTP error occurred.',
                'details': str(e)
            })
        }
    except Exception as e:
        debug_info = {
            'error_message': str(e),
            'request_time': datetime.utcnow().isoformat(),
            'requested_website': target,
            'event': event,
            'error_id': str(uuid.uuid4()),
        }
        debug_info_json = json.dumps(debug_info)
        
        # Try to upload to S3
        try:
            s3.put_object(Body=debug_info_json, Bucket=bucket_name, Key=f'debug_info_{context.aws_request_id}.json')
        except Exception as s3_e:
            print(f"Failed to upload debug info to S3: {str(s3_e)}")

        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Unexpected error occurred.',
                'debug_info': debug_info
            })
        }
