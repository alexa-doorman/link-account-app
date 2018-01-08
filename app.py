import os
from datetime import datetime, timedelta
import logging
import json
from decimal import Decimal

from os.path import join, dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

from flask import Flask, request, make_response, jsonify, render_template, redirect, url_for, session
import flask_login
from flask_oauthlib.provider import OAuth2Provider

import requests

from tables.users_table import UsersTable
from tables.user import User
import oauth_client

logger = logging.getLogger('app')
logger.setLevel(logging.INFO)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)


app = Flask(__name__)

app.config['LWA'] = {
    'consumer_key': os.environ['DOORMAN_LWA_KEY'],
    'consumer_secret': os.environ['DOORMAN_LWA_SECRET']
}
app.config['DEBUG'] = os.environ.get('DEBUG') == 'True'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'CHANGE_IN_PRODUCTION')
if not app.debug:
    app.config['SERVER_NAME'] = os.environ.get('SERVER_NAME', '0.0.0.0')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
oauth = OAuth2Provider()
oauth.init_app(app)


@login_manager.user_loader
def user_loader(amazon_id):
    user_data = UsersTable(amazon_id).get()
    if user_data:
        user = User(user_data['amazon_id'])
        user.data = user_data
        return user


@app.errorhandler(404)
def page_not_found(error):
    return make_response(jsonify({'status': 404,
                                  'route': request.url,
                                  'message': 'Not Found'}), 404)


@app.errorhandler(500)
def internal_error(error):
    logger.exception(str(error))
    return make_response(jsonify({'status': 500,
                                  'route': request.url,
                                  'message': 'Internal Server Error'}), 500)


@oauth.clientgetter
def load_client(client_id):
    return oauth_client.StaticOAuthClient()


@oauth.grantgetter
def load_grant(client_id, code):
    info = UsersTable.get_grant(client_id=client_id, code=code)
    grant = info.get('oa_grant')
    if grant:
        grant = json.loads(grant)
        return oauth_client.Grant(user_id=info['amazon_id'],
                                  user=User(info['amazon_id']),
                                  client_id=grant['client_id'],
                                  client=oauth_client.StaticOAuthClient(),
                                  code=grant['code'],
                                  redirect_uri=grant['redirect_uri'],
                                  expires=datetime.strptime(
                                      grant['expires'], '%Y-%m-%d %H:%M:%S'),
                                  _scopes=grant['_scopes']
                                  )


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = {
        'client_id': client_id,
        'code': code['code'],
        'redirect_uri': request.redirect_uri,
        '_scopes': ' '.join(request.scopes),
        'expires': expires.strftime('%Y-%m-%d %H:%M:%S')
    }
    UsersTable(flask_login.current_user.id).update_set(
        oa_grant=json.dumps(grant), client_id=client_id, code=code['code'])
    return grant


@oauth.tokengetter
def load_token(access_token=None):
    if access_token:
        info = UsersTable.get_token_by_access_id(access_token)
        token = info['oa_token']
        if token:
            return oauth_client.Token(client_id=token['client_id'],
                                      client=oauth_client.StaticOAuthClient(),
                                      user_id=info['amazon_id'],
                                      token_type=token['token_type'],
                                      access_token=token['access_token'],
                                      refresh_token=token['refresh_token'],
                                      expires=datetime.strptime(
                                          token['expires'], '%Y-%m-%d %H:%M:%S'),
                                      _scopes=token['_scopes'])


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'token_type': token['token_type'],
        '_scopes': token['scope'],
        'expires': expires.strftime('%Y-%m-%d %H:%M:%S'),
        'client_id': request.client.client_id,
    }
    UsersTable(request.user.id).update_set(
        oa_token=json.dumps(tok), oa_access_token=token['access_token'])
    return tok


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'client_id' in request.args:
        session['oauth_flow_args'] = request.args

    elif request.args.get('oa') == 'continue':
        return redirect(url_for('authorize', **session['oauth_flow_args']))

    return render_template('index.html', client_id=app.config['LWA']['consumer_key'], form={})


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('.index', **request.args))


@app.route('/login')
def login():
    return render_template('login-check.html')


@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return redirect(url_for('index'))


@app.route('/oauth/errors')
@flask_login.login_required
def oauth_errors():
    return jsonify({'error': request.args['error']})


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@flask_login.login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if flask_login.current_user.data['yolo_endpoint'] is None or flask_login.current_user.data['client_endpoint'] is None:
        session['linking'] = True
        return redirect(url_for('index', **request.args))
    return True


@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    print(request.form)
    print(request.args)
    return None


@app.route('/verify')
def verify():
    if 'access_token' not in request.args:
        return make_response(jsonify({'status': 'error', 'message': 'access_token missing!'}), 400)
    check_request = requests.get(
        'https://api.amazon.com/auth/o2/tokeninfo?access_token={0}'.format(request.args['access_token']))
    data = check_request.json()
    if data['aud'] != app.config['LWA']['consumer_key']:
        return make_response(jsonify({'status': 'error', 'message': 'wrong client id'}), 400)
    profile_request = requests.get('https://api.amazon.com/user/profile',
                                   headers={'Authorization': 'bearer {0}'.format(request.args['access_token'])})
    profile_data = profile_request.json()
    user_table = UsersTable(profile_data['user_id'])
    if user_table.get() is None:
        user_table.create(name=profile_data['name'],
                          email=profile_data['email'],
                          access_token=request.args['access_token'])
        user_table.append_metadata({'message': 'new link',
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
    else:
        user_table.update_set(
            last_login=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    user = User(profile_data['user_id'])
    flask_login.login_user(user)
    return jsonify({'status': 'success'})


@app.route('/update', methods=['POST', 'GET'])
def update():
    if request.method == 'GET':
        return redirect(url_for('index'))

    yolo_endpoint = request.form['yolo_endpoint']
    client_endpoint = request.form['client_endpoint']
    failed_reach_message = "Failed to reach {0}"
    message = None
    decode_error = "Failed to decode JSON for {0}"

    try:
        logger.info('Hitting %s' % yolo_endpoint)
        with open(os.path.join(os.getcwd(), 'static/img/sample_person.jpg'), 'rb') as jpg:
            ping_yolo = requests.post(
                yolo_endpoint, timeout=6, files={'image': jpg})
            # make sure that objects were detected -
            if not ping_yolo.json()['results']:
                message = "YOLO API Object detection failed. Are you sure you are giving the right route (/detect)?"
                raise ValueError(message)
    except json.JSONDecodeError as e:
        logger.error(str(e))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'yolo_endpoint')
        return render_template('index.html', error={'message': decode_error.format(yolo_endpoint)}, form=request.form)
    except Exception as e:
        logger.error(str(e))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'yolo_endpoint')
        return render_template('index.html', error={'message': message or failed_reach_message.format(yolo_endpoint)}, form=request.form)

    yolo_stats = {
        'url': yolo_endpoint,
        'elapsed': Decimal(str(ping_yolo.elapsed.total_seconds()))
    }
    UsersTable(flask_login.current_user.id).update_set(
        yolo_endpoint=yolo_stats)

    try:
        logger.info('Hitting %s' % client_endpoint)
        ping_client = requests.get(client_endpoint, timeout=5)
        if not ping_client.json()['camera']:
            message = "Streaming client camera is not opened!"
            raise IOError(message)
    except json.JSONDecodeError as e:
        logger.error(str(e))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'client_endpoint')
        return render_template('index.html', error={'message': decode_error.format(client_endpoint)}, form=request.form)
    except Exception as e:
        logger.error(str(e))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'client_endpoint')
        return render_template('index.html', error={'message': message or failed_reach_message.format(client_endpoint)}, form=request.form)

    client_stats = {
        'url': client_endpoint,
        'elapsed': Decimal(str(ping_client.elapsed.total_seconds()))
    }
    UsersTable(flask_login.current_user.id).update_set(
        client_endpoint=client_stats)

    if session['linking']:
        return redirect(url_for('authorize', **session['oauth_flow_args']))

    return redirect(url_for('index'))


@app.route('/report', methods=['POST'])
def report():
    payload = request.get_json()
    print('skill got', payload)
    return 'OK'


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG') == 'True',
            host=os.environ.get('SERVER_NAME', '0.0.0.0'), port=5003)
