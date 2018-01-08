import os
from datetime import datetime
import logging
import json
from decimal import Decimal

from flask import Flask, request, make_response, jsonify, render_template, redirect, url_for
import flask_login
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


# Try to load secret file
if os.path.isfile(os.path.join(os.getcwd(), 'secret.py')):
    import secret
    os.environ['DOORMAN_LWA_KEY'] = secret.DOORMAN_LWA_KEY
    os.environ['DOORMAN_LWA_SECRET'] = secret.DOORMAN_LWA_SECRET
    os.environ['SECRET_KEY'] = secret.SECRET_KEY


app = Flask(__name__)

app.config['LWA'] = {
    'consumer_key': os.environ['DOORMAN_LWA_KEY'],
    'consumer_secret': os.environ['DOORMAN_LWA_SECRET']
}
app.config['DEBUG'] = os.environ.get('DEBUG') == 'True'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'CHANGE_IN_PRODUCTION')
app.config['SERVER_NAME'] = os.environ.get('SERVER_NAME', '0.0.0.0')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(amazon_id):
    user_data = UsersTable(amazon_id).get()
    if user_data:
        user = User()
        user.id = user_data['amazon_id']
        user.data = user_data
        return user


@app.errorhandler(404)
def page_not_found(error):
    return make_response(jsonify({'status': 404,
                                  'route': request.url,
                                  'message': 'Not Found'}), 404)


@app.errorhandler(500)
def page_not_found(error):
    logger.exception(str(error))
    return make_response(jsonify({'status': 500,
                                  'route': request.url,
                                  'message': 'Internal Server Error'}), 500)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', client_id=app.config['LWA']['consumer_key'], form={})


@app.route('/login')
def login():
    return render_template('login-check.html')


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return redirect(url_for('index'))


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
    user = User()
    user.id = profile_data['user_id']
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

    return redirect(url_for('index'))


@app.route('/report', methods=['POST'])
def report():
    payload = request.get_json()
    print('skill got', payload)
    return 'OK'


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG') == 'True',
            host=os.environ.get('SERVER_NAME', '0.0.0.0'), port=5003)
