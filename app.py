import os
from datetime import datetime, timedelta
import logging
import json
from decimal import Decimal
import uuid

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
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
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


@app.route('/', methods=['GET', 'POST'])
def index():
    if 'client_id' in request.args:
        session['oauth_flow_args'] = request.args
    if (flask_login.current_user.is_authenticated and
        flask_login.current_user.data.get('yolo_endpoint') and
        flask_login.current_user.data.get('client_endpoint') and
            session.get('linking')):
        session['linking'] = False
        if 'oauth_flow_args' in session:
            return redirect(url_for('authorize', **session['oauth_flow_args']))
        else:
            return redirect(url_for('authorize'))
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


@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')


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
                          access_token=request.args['access_token'],
                          upstream_key=uuid.uuid4().hex)
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
                yolo_endpoint,
                timeout=6,
                files={'image': jpg},
                auth=(request.form['yolo_endpoint_username'],
                      request.form['yolo_endpoint_password']))
            # make sure that objects were detected -
            if not ping_yolo.json()['results']:
                message = "YOLO API Object detection failed. Are you sure you are giving the right route (/detect)?"
                raise ValueError(message)
    except ValueError as ve:
        logger.error(str(ve))
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
        logger.info('Hitting %s', client_endpoint)
        ping_client = requests.get(client_endpoint,
                                   timeout=5,
                                   auth=(request.form['client_endpoint_username'],
                                         request.form['client_endpoint_password']))
        if not ping_client.json()['camera']:
            message = "Streaming client camera is not opened!"
            raise IOError(message)
    except ValueError as ve:
        logger.error(str(ve))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'client_endpoint')
        return render_template('index.html', error={'message': decode_error.format(client_endpoint)}, form=request.form)
    except Exception as e:
        logger.error(str(e))
        UsersTable(flask_login.current_user.id).remove_from_item(
            'client_endpoint')
        return render_template('index.html', error={'message': message or failed_reach_message.format(client_endpoint)}, form=request.form)

    # Now verify secret-key is set properly
    try:
        logger.info('Checking UPSTREAM_SECRET_KEY is correct')
        if client_endpoint.endswith('/'):
            verify_endpoint = '{0}{1}'.format(client_endpoint, 'verify-key')
        else:
            verify_endpoint = '{0}/{1}'.format(client_endpoint, '/verify-key')
        up_key_request = requests.get(verify_endpoint,
                                      auth=(request.form['client_endpoint_username'],
                                            request.form['client_endpoint_password']),
                                      json={'UPSTREAM_REPORT_KEY': flask_login.current_user.data['upstream_key']})
        if up_key_request.status_code != 200:
            return render_template('index.html', error={'message': failed_reach_message.format(verify_endpoint)}, form=request.form)
    except Exception as e:
        logger.error(str(e))
        return render_template('index.html', error={'message': failed_reach_message.format(verify_endpoint)}, form=request.form)

    client_stats = {
        'url': client_endpoint,
        'elapsed': Decimal(str(ping_client.elapsed.total_seconds()))
    }
    UsersTable(flask_login.current_user.id).update_set(
        client_endpoint=client_stats)

    if session['linking']:
        if 'oauth_flow_args' not in session:
            return render_template('/', error={'message': 'OAuthflow session arguments missing. Please try again.'})
        return redirect(url_for('authorize', **(session.get('oauth_flow_args'))))

    return redirect(url_for('index'))


@app.route('/report', methods=['POST'])
def report():
    payload = request.get_json()
    print('skill got', payload)
    return 'OK'


# avoid circular importing
from oauth_views import *
from ask_views import *


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG') == 'True',
            host=os.environ.get('SERVER_NAME', '0.0.0.0'), port=5003)
