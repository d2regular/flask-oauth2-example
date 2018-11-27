from flask import Flask, redirect, url_for, render_template, flash, request, \
    abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user, login_required
import requests
from urllib.parse import urlencode
from collections import namedtuple
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = 'authorization'

# configuration of OAUTH APP
OAUTH_APPS = {
    'vk': {
        'client_id': 'YOUR_APP_ID',  # insert your app_id
        'client_secret': 'YOUR_SECRET_KEY'  # insert your secret key
    }
}

VK_VERSION = '5.92'

Friend = namedtuple('Friend', 'username link')


class VKAPIRequestError(Exception):
    """VKAPIRequestError is called if an error occurred while working
    with the VK API"""
    pass


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(85), nullable=False, unique=True)
    username = db.Column(db.String(100), nullable=False)
    access_token = db.Column(db.String(85), nullable=False)


class VKSignIn:
    """It's implementation of 'OAuth 2.0 Authorization Framework' for vk.com"""

    def __init__(self):
        self.__provider = 'vk'
        self.__client_id = OAUTH_APPS[self.__provider]['client_id']
        self.__client_secret = OAUTH_APPS[self.__provider]['client_secret']
        self.__callback_url = url_for('oauth_callback',
                                      provider=self.__provider, _external=True)
        self.__access_token_url = 'https://oauth.vk.com/access_token'
        self.__authorize_url = 'https://oauth.vk.com/authorize'
        self.__base_url = 'https://api.vk.com/method/'
        self.__version = VK_VERSION
        self.__scope = 'friends, offline'

    def authorize(self):
        """redirect user to provider authorize page"""

        authorize_params = {'client_id': self.__client_id,
                            'redirect_uri': self.__callback_url,
                            'scope': self.__scope,
                            'response_type': 'code',
                            'v': self.__version}
        url = '?'.join([self.__authorize_url, urlencode(authorize_params)])
        return redirect(url)

    def callback(self):
        """return data of the user who authorized the app"""

        # handle the request response for authorization of the app
        if 'error' in request.args:
            raise VKAPIRequestError

        try:
            # request user access token
            access_token_params = {'client_id': self.__client_id,
                                   'client_secret': self.__client_secret,
                                   'redirect_uri': self.__callback_url,
                                   'code': request.args['code']}
            access_token_r = requests.get(self.__access_token_url,
                                          params=access_token_params)
            access_token_data = access_token_r.json()

            if access_token_r.status_code != 200 or \
                    access_token_data.get('error', None):
                raise VKAPIRequestError

            access_token = access_token_data['access_token']
            social_id = access_token_data['user_id']

            # request user data
            user_params = {'user_id': social_id, 'v': self.__version,
                           'access_token': access_token}
            url = self.__base_url + 'users.get'
            user_r = requests.get(url, params=user_params)
            user_data = user_r.json()

            if user_r.status_code != 200 or \
                    user_data.get('error', None):
                raise VKAPIRequestError

            user = user_data['response'][0]
            first_name = user['first_name']
            last_name = user['last_name']
            username = ' '.join([first_name, last_name])
        except (ValueError, IndexError, KeyError):
            raise VKAPIRequestError

        return social_id, username, access_token


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authorization'))


@app.route('/authorization')
def authorization():
    return render_template('authorization.html', title='authorization')


@app.route('/')
@app.route('/index')
@login_required
def index():
    try:
        friends = get_vk_friends()
    except VKAPIRequestError:
        flash('Authorization failed.')
        return redirect(url_for('logout'))
    return render_template('index.html', title='Home', friends=friends)


def get_vk_friends():
    """get five random fiends of user from vk.com"""

    access_token = current_user.access_token
    social_id = current_user.social_id
    request_url = 'https://api.vk.com/method/friends.get'
    params = {'user_id': social_id, 'order': 'random', 'count': 5,
              'fields': 'nickname', 'v': VK_VERSION,
              'access_token': access_token}
    try:
        friends_r = requests.get(request_url, params=params)
        if friends_r.status_code != 200 or \
                friends_r.json().get('error', None):
            raise VKAPIRequestError

        friends = []
        for friend in friends_r.json()['response']['items']:
            link = 'https://vk.com/id' + str(friend['id'])
            username = friend['first_name'] + friend['last_name']
            friends.append(Friend(username, link))
    except (ValueError, KeyError):
        raise VKAPIRequestError
    return friends


@app.route('/authorization/<provider>')
def oauth_authorize(provider):
    if provider.lower() not in OAUTH_APPS.keys():
        return abort(404)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if provider.lower() == 'vk':
        oauth = VKSignIn()
        return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    if provider.lower() not in OAUTH_APPS.keys():
        return abort(404)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if provider.lower() == 'vk':
        oauth = VKSignIn()
        try:
            social_id, username, access_token = oauth.callback()
        except VKAPIRequestError:
            flash('Authentication failed.')
            return redirect(url_for('authorization'))
        user = User.query.filter_by(social_id=social_id).first()
        if not user:
            user = User(social_id=social_id, username=username,
                        access_token=access_token)
            db.session.add(user)
            db.session.commit()
        else:
            User.query.filter_by(id=user.id).update(
                {'access_token': access_token})
            db.session.commit()
        login_user(user, True)
        return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.debug = True
    app.run(host='localhost')
