import os


class StaticOAuthClient(object):
    client_id = os.environ['OA_CLIENT_ID']
    client_secret = os.environ['OA_CLIENT_SECRET']

    # public or confidential
    is_confidential = False

    _redirect_uris = os.environ['OA_REDIRECT_URIS']
    _default_scopes = os.environ['OA_SCOPES']

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split(',')
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(object):
    def __init__(self, user_id, user, client_id, client, code, redirect_uri, expires, _scopes):
        self.user_id = user_id
        self.user = user
        self.client_id = client_id
        self.client = client
        self.code = code
        self.redirect_uri = redirect_uri
        self.expires = expires
        self._scopes = _scopes

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def delete(self):
        pass


class Token(object):
    def __init__(self, client_id, client, user_id, token_type, access_token, refresh_token, expires, _scopes):
        self.client_id = client_id
        self.client = client
        self.user_id = user_id
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires = expires
        self._scopes = _scopes

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def delete(self):
        pass