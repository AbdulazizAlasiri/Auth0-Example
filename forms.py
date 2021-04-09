from datetime import datetime
from flask_wtf import Form
from wtforms import StringField, SelectField, SelectMultipleField, DateField, BooleanField
from wtforms.validators import DataRequired, AnyOf, URL
from wtforms import ValidationError
import re


class CreditCardForm(Form):
    number = StringField(
        'number', validators=[DataRequired()]
    )

    expiration = StringField(
        'expiration', validators=[DataRequired()]
    )

    card_holder = StringField(
        'card_holder', validators=[DataRequired()]
    )
    address = StringField(
        'address', validators=[DataRequired()]
    )


class ProfileForm(Form):
    full_name = StringField(
        'full_name', validators=[DataRequired()]
    )

    phone = StringField(
        'phone', validators=[DataRequired()]
    )

    date_of_birth = DateField(
        'date_of_birth',
        validators=[DataRequired()],
        default=datetime.today().date()
    )
