import logging
from functools import wraps

from flask_ask import Ask, statement, question

from app import app, request, session


logger = logging.getLogger()

ask = Ask(app, '/alexa')


@ask.default_intent
def default_intent():
    logger.info('intent not routed')
    logger.info(request)


def link_account_response():
    return statement('Please use the Alexa app to link your Doorman account').link_account_card()


def has_access_token(f):
    # Adapted from [johnwheeler/flask-ask] Decorators for ask.intent (#176)
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user', {}).get('accessToken'):
            return link_account_response()

        slots = request.get('intent', {}).get('slots')
        for key, value in slots.iteritems():
            kwargs.update({key: value.get('value')})

        return f(*args, **kwargs)
    return decorated_function


@ask.launch
@has_access_token
def launch():
    card_title = 'Doorman - check who (or what) is at the door'
    text = ('Doorman can tell you if someone or something is at the door. Doorman can also ' +
            'provide you the link to view a feed of your camera. You can also enable the ' +
            'Doorman Streamer Smart Home Skill to access your camera on a capable device. ')
    prompt = ('Would you like me to check what is ' +
              'at the door or would you like to get a link to view your web camera?')
    return question(text + prompt).reprompt(prompt).simple_card(card_title, text)


@ask.intent('AMAZON.StopIntent')
def stop_intent():
    if app.debug:
        logger.info('stop intent')
    return statement("Stopped.")


@ask.intent('AMAZON.CancelIntent')
def cancel_intent():
    if app.debug:
        logger.info('cancel intent')
    return statement("Canceled.")


@ask.intent('AMAZON.HelpIntent')
def help_intent():
    speech = ('Help intent')
    return question(speech).simple_card('Help')


@ask.intent('StreamIntent')
@has_access_token
def stream_intent():
    speech = ('Stream intent')
    return statement(speech).simple_card('Help')


@ask.intent('CheckDoorIntent')
@has_access_token
def check_door_intent():
    speech = ('check door intent')
    return statement(speech).simple_card('Help')
