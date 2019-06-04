import zlib
import boto3
import base64
import json
import os
import aws_encryption_sdk
import hashlib
from dateutil import parser
from Cryptodome.Cipher import AES
from aws_encryption_sdk import DefaultCryptoMaterialsManager
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

key_id = os.environ['KEY_ID']
stream_name = os.environ['STREAM_NAME']
region_name = os.environ['AWS_REGION']
cluster_id = os.environ['CLUSTER_ID']

class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"

    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj

    def __init__(self, wrapping_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = wrapping_key

    def _get_raw_key(self, key_id):
        return self.wrapping_key


def process_entries(entries):
    findings = []
    for entry in entries:
        finding_id = hashlib.md5(json.dumps(entry).encode('utf-8')).hexdigest()
        title = 'Unusual Database Behaviour'
        finding_types = [
            'Unusual Behaviors/Database'
        ]

        entry_timestamp = str(entry['logTime'])
        entry_class = str(entry['class'])
        entry_base_command = str(entry['command'])
        entry_command = str(entry['commandText'])
        entry_ip = str(entry['remoteHost'])
        entry_dbname = str(entry['databaseName'])
        entry_username = str(entry['dbUserName'])
        entry_rowcount = str(entry['rowCount']) if entry['rowCount'] else "0"

        if entry_username == "rdsadmin":
            continue

        severity = 0
        if entry_class == "ROLE":
            finding_types.append('TTPs/Privilege Escalation')
            finding_types.append('TTPs/Persistence')
            finding_types.append('Effects/Data Exfiltration')
            finding_types.append('Effects/Denial of Service')
            severity = 9.9
            title = 'Database Role Adjustment'
        elif entry_class == "MISC":
            if entry_base_command == "AUTH FAILURE":
                finding_types.append('TTPs/Initial Access')
                finding_types.append('Effects/Data Exposure')
                severity = 5
                title = 'Database Failed Authentication Attempt'
            else:
                continue
        elif entry_class == "READ":
            if "pg_catalog" in entry_command:
                finding_types.append('TTPs/Discovery')
                finding_types.append('Effects/Data Exfiltration')
                severity = 2
                title = 'Database Catalog Enumeration'
            else:
                continue
        elif entry_class == "DDL":
            if entry_base_command == "DROP TABLE":
                finding_types.append('TTPs/Execution')
                finding_types.append('Effects/Data Destruction')
                severity = 9.5
                title = 'Database Table Dropped'
            else:
                continue
        elif entry_class == "WRITE":
            if entry_base_command == "TRUNCATE TABLE":
                finding_types.append('TTPs/Execution')
                finding_types.append('Effects/Data Destruction')
                severity = 9.5
                title = 'Database Table Truncated'
            else:
                continue
        else:
            continue
        
        description = "Database action performed by {}: {}".format(entry_username, entry_command)

        findings.append({
            'SchemaVersion': '2018-10-08',
            'Id': finding_id,
            'ProductArn': 'arn:aws:securityhub:{}:{}:product/{}/default'.format(os.environ['AWS_REGION'], os.environ['ACCOUNTID'], os.environ['ACCOUNTID']),
            'GeneratorId': 'sql-activity-stream',
            'AwsAccountId': os.environ['ACCOUNTID'],
            'Types': finding_types,
            'FirstObservedAt': parser.parse(entry_timestamp).strftime("%Y-%m-%dT%H:%M:%SZ"),
            'LastObservedAt': parser.parse(entry_timestamp).strftime("%Y-%m-%dT%H:%M:%SZ"),
            'CreatedAt': parser.parse(entry_timestamp).strftime("%Y-%m-%dT%H:%M:%SZ"),
            'UpdatedAt': parser.parse(entry_timestamp).strftime("%Y-%m-%dT%H:%M:%SZ"),
            'Severity': {
                'Product': float(severity),
                'Normalized': int(severity*10)
            },
            'Confidence': 100,
            'Criticality': 100,
            'Title': title,
            'Description': (description[:1020] + '...') if len(description) > 1023 else description,
            'ProductFields': {
                'SQLCommand': entry_command,
                'SQLBaseCommand': entry_base_command,
                'SQLClass': entry_class,
                'IpAddress': entry_ip,
                'RowCount': entry_rowcount,
                'DbName': entry_dbname,
                'UserName': entry_username
            },
            'Resources': [
                {
                    'Id': cluster_id,
                    'Type': 'Other'
                }
            ]
        })

    if len(findings) > 0:
        securityhub = boto3.client('securityhub')

        response = securityhub.batch_import_findings(
            Findings=findings
        )
        if response['FailedCount'] > 0:
            print("Failed to import {} findings".format(response['FailedCount']))


def decrypt(decoded, plaintext):
    wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                               wrapping_key=plaintext, wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    my_key_provider = MyRawMasterKeyProvider(wrapping_key)
    my_key_provider.add_master_key("DataKey")
    with aws_encryption_sdk.stream(
            mode='d',
            source=decoded,
            materials_manager=DefaultCryptoMaterialsManager(master_key_provider=my_key_provider)
    ) as decryptor:
        entries = []
        for chunk in decryptor:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decompressed_database_stream = d.decompress(chunk)
            record_event = json.loads(decompressed_database_stream.decode("utf-8"))
            for evt in record_event['databaseActivityEventList']:
                if evt['type'] != "heartbeat":
                    entries.append(evt)
        if len(entries) > 0:
            process_entries(entries)


def lambda_handler(event, context):
    session = boto3.session.Session()

    kms = session.client('kms', region_name=region_name)

    for record in event['Records']:
        record_data = json.loads(base64.b64decode(record['kinesis']['data']))
        decoded = base64.b64decode(record_data['databaseActivityEvents'])
        decoded_data_key = base64.b64decode(record_data['key'])
        decrypt_result = kms.decrypt(CiphertextBlob=decoded_data_key,
                                     EncryptionContext={"aws:rds:dbc-id": cluster_id})
        decrypt(decoded, decrypt_result[u'Plaintext'])
