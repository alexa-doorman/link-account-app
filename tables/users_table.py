import json
import logging

import boto3
from boto3.dynamodb.conditions import Key, Attr

logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('nose').setLevel(logging.WARNING)

# Get the service resource.
DYNAMODB = boto3.resource('dynamodb')
USERS_TABLE = DYNAMODB.Table('users')


class UsersTable(object):
    def __init__(self, amazon_id):
        # Instantiate a table resource object without actually
        # creating a DynamoDB table. Note that the attributes of this table
        # are lazy-loaded: a request is not made nor are the attribute
        # values populated until the attributes
        # on the table resource are accessed or its load() method is called.
        self.table = USERS_TABLE
        self.amazon_id = amazon_id

    def get(self):
        return self.table.get_item(Key={'amazon_id': self.amazon_id}).get('Item')

    @staticmethod
    def get_grant(client_id, code):
        user = USERS_TABLE.scan(FilterExpression=Attr('client_id').eq(
            client_id) & Attr('code').eq(code)).get('Items')
        if user:
            return user[0]

    @staticmethod
    def get_token_by_access_id(oa_access_token):
        user = USERS_TABLE.scan(FilterExpression=Attr(
            'oa_access_token').eq(oa_access_token)).get('Items')
        if user:
            return user[0]

    @staticmethod
    def get_token_by_client_id(client_id, amazon_id=None):
        if amazon_id:
            user = USERS_TABLE.scan(FilterExpression=Attr('client_id').eq(
                client_id) & Attr('amazon_id').eq(amazon_id)).get('Items')[:1]
        else:
            user = USERS_TABLE.scan(FilterExpression=Attr(
                'client_id').eq(client_id)).get('Items')
        if user:
            return user[0]['oa_token']

    def create(self, name, email, access_token):
        self.table.put_item(Item={'amazon_id': self.amazon_id,
                                  'name': name,
                                  'email': email,
                                  'access_token': access_token})

    def put_error(self, error_message):
        self.update_set(error_messages=json.dumps(error_message))

    def append_metadata(self, metadata):
        item = self.get()
        data = item.get('metadata')
        if data is not None:
            item_metadata = json.loads(data)
        else:
            item_metadata = []
        item_metadata.append(metadata)
        self.update_set(metadata=json.dumps(item_metadata))

    def update_set(self, **kwargs):
        self.table.update_item(
            Key={'amazon_id': self.amazon_id},
            UpdateExpression='SET ' + ', '.join(
                '{0} = :{0}val'.format(k) for k in kwargs.keys()),
            ExpressionAttributeValues={
                ':{0}val'.format(k): v for k, v in kwargs.items()}
        )

    def remove_from_item(self, keys):
        if isinstance(keys, str):
            keys = [keys]
        self.table.update_item(
            Key={'amazon_id': self.amazon_id},
            UpdateExpression='REMOVE ' + ', '.join(keys))

    def delete(self):
        self.table.delete_item(Key={'amazon_id': self.amazon_id})
