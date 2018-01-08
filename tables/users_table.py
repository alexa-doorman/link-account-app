import json

import boto3

# Get the service resource.
dynamodb = boto3.resource('dynamodb')


class UsersTable(object):
    def __init__(self, amazon_id):
        # Instantiate a table resource object without actually
        # creating a DynamoDB table. Note that the attributes of this table
        # are lazy-loaded: a request is not made nor are the attribute
        # values populated until the attributes
        # on the table resource are accessed or its load() method is called.
        self.table = dynamodb.Table('users')
        self.amazon_id = amazon_id

    def get(self):
        return self.table.get_item(Key={'amazon_id': self.amazon_id}).get('Item')

    def create(self, name, email, access_token):
        self.table.put_item(Item={'amazon_id': self.amazon_id,
                                  'name': name,
                                  'email': email,
                                  'access_token': access_token})

    def put_error(self, error_message):
        item = self.get()
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
            UpdateExpression=', '.join(
                'SET {0} = :{0}val'.format(k) for k in kwargs.keys()),
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
