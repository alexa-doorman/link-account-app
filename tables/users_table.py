import boto3

# Get the service resource.
dynamodb = boto3.resource('dynamodb')


class UsersTable(object):
    def __init__(self):
        # Instantiate a table resource object without actually
        # creating a DynamoDB table. Note that the attributes of this table
        # are lazy-loaded: a request is not made nor are the attribute
        # values populated until the attributes
        # on the table resource are accessed or its load() method is called.
        self.table = dynamodb.Table('users')

    def get(self, amazon_id):
        return self.table.get_item(Key={'amazon_id': amazon_id})['Item']

    def put(self, amazon_id, **kwargs):
        self.table.put_item(Item=kwargs)

    def update_set(self, amazon_id, **kwargs):
        self.table.update_item(
            Key={'amazon_id': amazon_id},
            UpdateExpression=', '.join(
                'SET {0} = :{0}val'.format(k) for k in kwargs.keys()),
            ExpressionAttributeValues={
                '{0}val'.format(k): v for k, v in kwargs.items()}
        )

    def delete(self, amazon_id):
        self.table.delete_item(Key={'amazon_id': amazon_id})
