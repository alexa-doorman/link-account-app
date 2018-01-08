from flask_login import UserMixin

from tables.users_table import UsersTable


class User(UserMixin):
    def __init__(self, _id):
        self.id = _id
