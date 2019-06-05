import boto3
import os
import requests
import json
import sys
import time


def send_response(event, context, response_status, response_data, physical_resource_id):
    response_object = {
        "Status": response_status,
        "PhysicalResourceId": physical_resource_id,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    }

    if response_status != "SUCCESS":
        if 'ErrorMessage' in response_data:
            response_object['Reason'] = response_data['ErrorMessage']
        else:
            response_object['Reason'] = "See the details in CloudWatch Log Stream: " + context.log_stream_name
    
    response_body = json.dumps(response_object)
    requests.put(event['ResponseURL'], data=response_body)


def lambda_handler(event, context):
    try:
        rdsclient = boto3.client('rds')
        kinesisclient = boto3.client('kinesis')

        clusters = rdsclient.describe_db_clusters(
            DBClusterIdentifier=os.environ['CLUSTER']
        )['DBClusters']

        if len(clusters) != 1:
            send_response(event, context, "FAILED", {"ErrorMessage": "Cluster not found"}, 'DbClusterActivityStream')
            quit()
        
        if event['RequestType'] == "Delete":
            streamresponse = rdsclient.stop_activity_stream(
                ResourceArn=os.environ['CLUSTER'],
                ApplyImmediately=True
            )
        else:
            streamresponse = rdsclient.start_activity_stream(
                ResourceArn=os.environ['CLUSTER'],
                Mode=os.environ['SYNC_MODE'],
                KmsKeyId=os.environ['KEY_ID'],
                ApplyImmediately=True
            )
            
            streamactive = False
            while not streamactive:
                time.sleep(10)
                try:
                    response = kinesisclient.describe_stream(
                        StreamName=streamresponse['KinesisStreamName']
                    )
                    if response['StreamDescription']['StreamStatus'] == "ACTIVE":
                        streamactive = True
                except:
                    pass

        send_response(event, context, "SUCCESS", {
            'ClusterId': clusters[0]['DbClusterResourceId'],
            'StreamName': streamresponse['KinesisStreamName']
        }, 'DbClusterActivityStream')
    except Exception as e:
        print("Unexpected error:", str(e))
        send_response(event, context, "FAILED", {"ErrorMessage": str(e)}, 'DbClusterActivityStream')
