import logging
from datetime import datetime, timedelta
import json

import flask_login
from flask import request, jsonify, redirect, url_for, session

from app import app, oauth
from tables.users_table import UsersTable
from tables.user import User
import oauth_client

logger = logging.getLogger()


def get_code_grant_key(client_id):
    if client_id == oauth_client.StreamOAuthClient.client_id:
        code_key = "stream_code"
        grant_key = "stream_grant"
    elif client_id == oauth_client.QueryOAuthClient.client_id:
        code_key = "query_code"
        grant_key = "query_grant"
    else:
        raise ValueError("Invalid client id {0}!".format(client_id))
    return code_key, grant_key


def resolve_client(client_id):
    if client_id == oauth_client.StreamOAuthClient.client_id:
        return oauth_client.StreamOAuthClient()
    elif client_id == oauth_client.QueryOAuthClient.client_id:
        return oauth_client.QueryOAuthClient()
    else:
        raise ValueError("Invalid client id {0}!".format(client_id))


@oauth.clientgetter
def load_client(client_id):
    return resolve_client(client_id)


@oauth.grantgetter
def load_grant(client_id, code):
    code_key, grant_key = get_code_grant_key(client_id)

    info = UsersTable.get_grant(code_key=code_key, code=code)
    grant = info.get(grant_key)
    if grant:
        grant = json.loads(grant)
        return oauth_client.Grant(user_id=info['amazon_id'],
                                  user=User(info['amazon_id']),
                                  client_id=grant['client_id'],
                                  client=resolve_client(client_id),
                                  code=grant['code'],
                                  redirect_uri=grant['redirect_uri'],
                                  expires=datetime.strptime(
                                      grant['expires'], '%Y-%m-%d %H:%M:%S'),
                                  _scopes=grant['_scopes'])


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)

    code_key, grant_key = get_code_grant_key(client_id)

    grant = {
        'client_id': client_id,
        'code': code['code'],
        'redirect_uri': request.redirect_uri,
        '_scopes': ' '.join(request.scopes),
        'expires': expires.strftime('%Y-%m-%d %H:%M:%S')
    }

    updates = {
        grant_key: json.dumps(grant),
        code_key: code['code']
    }

    UsersTable(flask_login.current_user.id).update_set(**updates)
    return grant


def get_token_keys(client_id):
    if client_id == oauth_client.StreamOAuthClient.client_id:
        data_key = "stream_token_data"
        token_key = "stream_token"
    elif client_id == oauth_client.QueryOAuthClient.client_id:
        data_key = "query_token_data"
        token_key = "query_token"
    else:
        raise ValueError("Invalid client id {0}!".format(client_id))

    return data_key, token_key


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)
    data_key, token_key = get_token_keys(request.client.client_id)

    tok = {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'token_type': token['token_type'],
        '_scopes': token['scope'],
        'expires': expires.strftime('%Y-%m-%d %H:%M:%S'),
        'client_id': request.client.client_id,
    }

    updates = {
        data_key: json.dumps(tok),
        token_key: token['access_token']
    }

    UsersTable(request.user.id).update_set(**updates)
    return tok


@oauth.tokengetter
def load_token(oa_access_token=None):
    if oa_access_token:
        info = UsersTable.get_token_by_access_id(oa_access_token)
        if info:
            # data_key, token_key = get_token_keys(request.client.client_id)
            if oa_access_token == info.get('stream_token'):
                token = info['stream_token_data']
                client = oauth_client.StreamOAuthClient()
            elif oa_access_token == info.get('query_token'):
                token = info['query_token_data']
                client = oauth_client.QueryOAuthClient()
            else:
                raise ValueError("Token types mismatch")

            if token:
                return oauth_client.Token(client_id=token['client_id'],
                                          client=client,
                                          user_id=info['amazon_id'],
                                          token_type=token['token_type'],
                                          access_token=token['access_token'],
                                          refresh_token=token['refresh_token'],
                                          expires=datetime.strptime(
                                              token['expires'], '%Y-%m-%d %H:%M:%S'),
                                          _scopes=token['_scopes'])


@app.route('/oauth/errors')
@flask_login.login_required
def oauth_errors():
    return jsonify({'error': request.args['error']})


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    session['linking'] = True
    if flask_login.current_user.is_authenticated:
        if (flask_login.current_user.data.get('yolo_endpoint') is None or
                flask_login.current_user.data.get('client_endpoint') is None):
            return redirect(url_for('index', **request.args))
        return True
    else:
        return redirect(url_for('index', **request.args))


@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    logger.info("Token request from IP %s", str(
        request.headers.getlist("X-Forwarded-For")))
    return None
