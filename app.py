#!/usr/bin/env python
import base64
import logging
import os

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    session,
    url_for,
)
from flask_oauthlib.client import OAuth
from flask_socketio import SocketIO

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.getenv('APP_SECRET_KEY',
                            base64.b64encode(os.urandom(16)).decode('utf-8')),
})
oauth = OAuth(app)
socketio = SocketIO(app)

google = oauth.remote_app('google',
                          consumer_key=os.environ['APP_CONSUMER_KEY'],
                          consumer_secret=os.environ['APP_CONSUMER_SECRET'],
                          request_token_params={
                            'scope': 'email',
                        },
                        base_url='https://www.googleapis.com/oauth2/v1/',
                        request_token_url=None,
                        access_token_method='POST',
                        access_token_url='https://accounts.google.com/o/oauth2/token',
                        authorize_url='https://accounts.google.com/o/oauth2/auth')


@socketio.on('connect')
def on_user_connect():
    if session.get('user'):
        logger.info('User connected: %s', session['user'])
        socketio.emit('user_connected', {
            'user': session['user'],
        })
    else:
        logger.info('No user provided, refusing connection.')
        return False


@socketio.on('disconnect')
def on_user_disconnect():
    logger.info('User disconnected: %s', session['user'])
    socketio.emit('user_disconnected', {
        'user': session['user'],
    })


@socketio.on('message')
def on_message(message):
    logger.info('New message: %s', message)
    socketio.emit('message', {
        'user': session['user'],
        'message': message,
    })


@google.tokengetter
def get_google_oauth_token():
    """Get the token used for google oauth2"""
    return session.get('google_token'), ''


@app.route('/login/google')
def login_google():
    """Initiate the google oauth2 flow"""
    logger.info('Logging user in with google')
    return google.authorize(callback=url_for('google_callback',
                                             _external=True))


@app.route('/login/google/callback')
def google_callback():
    """Handle the google oauth2 callback"""
    resp = google.authorized_response()
    if resp is None:
        logger.info('User denied OAuth2 request')
        return 'Access Denied!'
    session['google_token'] = resp['access_token']
    session['user'] = google.get('userinfo').data
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logger.info('User logging out')
    session.pop('google_token', None)
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    logger.info('Booting...')
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('APP_PORT', 5000)))

