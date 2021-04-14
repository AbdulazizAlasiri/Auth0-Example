from datetime import datetime
from flask_wtf import Form
from wtforms import StringField, SelectField, SelectMultipleField, DateField, BooleanField, SubmitField
from wtforms.validators import DataRequired, AnyOf, Length, Regexp
from wtforms import ValidationError
from datetime import date


class CreditCardForm(Form):
    number = StringField(
        'number', validators=[DataRequired(), Regexp(r'^[0-9]{12}$', message='Credit card number must be in the form of xxxx xxxx xxxx xxxx')]
    )

    expiration = StringField(
        'expiration', validators=[DataRequired(), Regexp(regex=r'^(0[1-9]|1[0-2])\/([0-9]{2}|[0-9]{2})$', message='Expiration date must be in the form MM/YY')]
    )

    card_holder = StringField(
        'card_holder', validators=[DataRequired(), Length(min=2, max=25, message="Card holder name must be betwen 5 & 25 characters")]
    )
    address = StringField(
        'address', validators=[DataRequired()]
    )


class ProfileForm(Form):

    full_name = StringField(
        'full_name', validators=[DataRequired(), Length(min=2, max=25, message="Your must be betwen 5 & 25 characters")]
    )

    phone = StringField(
        'phone', validators=[DataRequired(), Regexp(regex=r'\+?(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)(\d{9})$', message='Phone number must be in the form of +xxx xxxxx xxxx')]
    )

    date_of_birth = DateField(
        'date_of_birth',
        validators=[DataRequired(), ],

        default=datetime.today().date().replace(year=datetime.today().date().year-13)
    )

    def validate_date_of_birth(form, field):
        today = date.today()
        valid = date.today().replace(year=today.year-13)
        if field.data > valid:
            if field.data > today:
                raise ValidationError('Please enter a valid date')
            else:
                raise ValidationError('You must be older than 13')
