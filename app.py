#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, request, Response, flash, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_moment import Moment
from flask_migrate import Migrate


from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
import babel
import dateutil.parser
import logging
from logging import Formatter, FileHandler
from forms import *
import sys
import os
from os import environ as env
from functools import wraps
from cryptography.fernet import Fernet

import constants

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

app = Flask(__name__)
moment = Moment(app)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


#----------------------------------------------------------------------------#
# Models.
#----------------------------------------------------------------------------#


class User(db.Model):
    __tablename__ = 'users'
    auth0_id = db.Column(db.String,  primary_key=True)
    full_name = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, unique=False)
    birth_day = db.Column(db.DateTime, nullable=False)
    credit_cards = db.relationship(
        'CreditCard', backref='user', cascade="all, delete-orphan", lazy=True)


class CreditCard(db.Model):
    __tablename__ = 'credit_cards'

    id = db.Column(db.Integer, primary_key=True)
    number = db.Column((db.String), nullable=False, unique=False)
    expiration = db.Column(db.String, nullable=False)

    card_holder = db.Column(db.String, nullable=False)
    address = db.Column(db.String, nullable=False)
    user_id = db.Column(db.String, db.ForeignKey(
        'users.auth0_id'), nullable=False)


#----------------------------------------------------------------------------#
# Filters.
#----------------------------------------------------------------------------#


def encrypt_data(data):
    """
    Encrypts a message
    """
    key = app.secret_key
    encoded_data = data.encode()
    f = Fernet(key)
    encrypted_data = f.encrypt(encoded_data)
    return encrypted_data


def decrypt_data(encrypted_data):
    """
    Decrypts an encrypted message
    """
    key = app.secret_key
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data


def format_datetime(value, format='medium'):
    date = dateutil.parser.parse(value)
    if format == 'full':
        format = "EEEE MMMM, d, y 'at' h:mma"
    elif format == 'medium':
        format = "EE MM, dd, y h:mma"
    return babel.dates.format_datetime(date, format, locale='en')


app.jinja_env.filters['datetime'] = format_datetime

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#


@app.route('/')
def index():

    profile = session.get(constants.PROFILE_KEY)
    if profile is not None:
        user_id = profile['user_id']
        user = User.query.get(user_id)
        if user is None:
            return redirect(url_for('profile_form'))

        else:
            cards = [{'number': decrypt_data(card.number), 'expiration': decrypt_data(card.expiration), 'card_id': card.id}
                     for card in user.credit_cards]
            data = {
                'user_id': user_id,
                'full_name': user.full_name,
                'credit_cards': cards
            }
            return render_template('pages/home.html', user=data)

    return render_template('pages/home.html', user={})


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for(
        'index', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

#  Profile
#  ----------------------------------------------------------------


@app.route('/profile', methods=['GET'])
@requires_auth
def profile_form():
    profile = session.get(constants.PROFILE_KEY)
    user_id = profile['user_id']
    user = User.query.get(user_id)
    if not user is None:
        return redirect('/')
    form = ProfileForm()
    data = {'user_id': user_id}
    return render_template('forms/profile.html', form=form, user=data)


@app.route('/profile', methods=['POST'])
@requires_auth
def profile_submission():
    error = False
    form = request.form

    try:
        user = User(auth0_id=session[constants.PROFILE_KEY]['user_id'],
                    full_name=form['full_name'], phone=form['phone'], birth_day=form['date_of_birth'])
        db.session.add(user)
        db.session.commit()

    except:
        error = True
        print(sys.exc_info())
    finally:
        db.session.rollback()
        db.session.close()
    if error:
        flash('An error occurred. User ' +
              form['full_name'] + ' could not be listed.')
    else:
        flash('User ' + form['full_name'] + ' was successfully listed!')

    return redirect(url_for('index'))

#  Credit Card
#  ----------------------------------------------------------------


@app.route('/credit-card', methods=['GET'])
@requires_auth
def credit_card_form():
    profile = session.get(constants.PROFILE_KEY)
    user_id = profile['user_id']
    user = User.query.get(user_id)
    if user is None:
        return redirect('/')
    form = CreditCardForm()
    data = {'user_id': user_id}
    return render_template('forms/credit_card.html', form=form, user=data)


@app.route('/credit-card', methods=['POST'])
@requires_auth
def credit_card_submission():
    error = False
    form = request.form

    enc_number = encrypt_data(form['number'])
    enc_expiration = encrypt_data(form['expiration'])
    enc_card_holder = encrypt_data(form['card_holder'])
    try:
        card = CreditCard(number=enc_number, expiration=enc_expiration, card_holder=encrypt_data(form['card_holder']),
                          address=encrypt_data(form['address']), user_id=session[constants.PROFILE_KEY]['user_id'])
        db.session.add(card)
        db.session.commit()

    except:
        db.session.rollback()
        error = True
        print(sys.exc_info())
    finally:
        db.session.close()
    if error:
        flash('An error occurred. Card ' +
              form['number'] + ' could not be added.')
    else:
        flash('User ' + form['number'] + ' was successfully listed!')

    return redirect(url_for('index'))


@app.route('/credit-card/<card_id>', methods=['DELETE'])
def credit_card_deletion(card_id):
    error = False

    try:
        card = CreditCard.query.get(card_id)
        db.session.delete(card)
        db.session.commit()

    except:
        db.session.rollback()
        error = True
        print(sys.exc_info())
    finally:
        db.session.close()
    if error:
        flash('An error occurred. Card ' +
              card.number + ' could not be deledted.')
    else:
        flash('Card ' + card.number + ' was successfully deledted!')

    return redirect(url_for('index'))


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html', user={}), 404


@app.errorhandler(500)
def server_error(error):
    return render_template('errors/500.html', user={}), 500


if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

# Default port:
'''
if __name__ == '__main__':
    app.run()
'''
# Or specify port manually:

if __name__ == '__main__':

    # db.drop_all()
    # db.create_all()

    port = int(os.environ.get('PORT', 3000))
    app.run(host='localhost', port=port)
