import logging
from functools import wraps

import flask_ask as ask

from app import app


logger = logging.getLogger()

ask_routes = ask.Ask(app, '/alexa')


@app.errorhandler(400)
def error_400(error):
    print("400 ERROR")
    logger.exception(request.data)


@ask_routes.default_intent
def default_intent():
    logger.info('intent not routed')
    logger.info(ask.request)


def link_account_response():
    return ask.statement('Please use the Alexa app to link your Doorman account').link_account_card()


def has_access_token(f):
    # Adapted from [johnwheeler/flask-ask] Decorators for ask.intent (#176)
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not ask.session.get('user', {}).get('accessToken'):
            return link_account_response()
        slots = ask.request.get('intent', {}).get('slots')
        intent_name = ask.request.get('intent', {}).get('name')
        if slots:
            if intent_name in ask_routes._intent_mappings:
                intent_map = {v: k for k,
                              v in ask_routes._intent_mappings[intent_name].items()}

            for key, value in slots.items():
                kwargs.update({intent_map.get(key, key): value.get('value')})

        return f(*args, **kwargs)
    return decorated_function


@ask_routes.launch
@has_access_token
def launch():
    card_title = 'Doorman - check who (or what) is at the door'
    text = ('Doorman can tell you if someone or something is at the door. Doorman can also ' +
            'provide you the link to view a feed of your camera. You can also enable the ' +
            'Doorman Streamer Smart Home Skill to access your camera on a capable device. ')
    prompt = ('Would you like me to check what is ' +
              'at the door or would you like to get a link to view your web camera?')
    return ask.question(text + prompt).reprompt(prompt).simple_card(card_title, text)


@ask_routes.intent('AMAZON.StopIntent')
def stop_intent():
    if app.debug:
        logger.info('stop intent')
    return ask.statement("Stopped.")


@ask_routes.intent('AMAZON.CancelIntent')
def cancel_intent():
    if app.debug:
        logger.info('cancel intent')
    return ask.statement("Canceled.")


@ask_routes.intent('AMAZON.HelpIntent')
def help_intent():
    speech = ('Help intent')
    return ask.question(speech).simple_card('Help')


@ask_routes.intent('StreamIntent', mapping={
    'stream_query': 'StreamQuery'
})
@has_access_token
def stream_intent(stream_query):
    speech = ('Stream intent')
    return ask.statement(speech).simple_card('Help')


@ask_routes.intent('CheckDoorIntent', mapping={
    'check_door_query': 'CheckDoorQuery'
})
@has_access_token
def check_door_intent(check_door_query):
    speech = ('check door intent')
    return ask.statement(speech).simple_card('Help')
