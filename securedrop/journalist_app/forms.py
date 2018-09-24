# -*- coding: utf-8 -*-

from flask_babel import lazy_gettext as gettext
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import (TextAreaField, TextField, BooleanField, HiddenField,
                     ValidationError, Field, SelectField)
from wtforms.validators import InputRequired, Optional

from models import Journalist


def otp_secret_validation(form, field):
    strip_whitespace = field.data.replace(' ', '')
    if len(strip_whitespace) != 40:
        raise ValidationError(gettext(
            'HOTP secrets are 40 characters long - '
            'you have entered {num_chars}.'.format(
                num_chars=len(strip_whitespace)
            )))


def minimum_length_validation(form, field):
    if len(field.data) < Journalist.MIN_USERNAME_LEN:
        raise ValidationError(
            gettext('Field must be at least {min_chars} '
                    'characters long but only got '
                    '{num_chars}.'.format(
                        min_chars=Journalist.MIN_USERNAME_LEN,
                        num_chars=len(field.data))))


class JournalistSelectField(SelectField):

    def __init__(self, *nargs, **kwargs):
        '''A select field that lists all current journalists.
           Has the kwargs 'is_optional' that specifices if a journalist must
           be selected on submit.
           :param *nargs: args passed to super()
           :param **kwargs: args passed to super()
        '''
        for arg in ['validators', 'choices', 'coerce']:
            if arg in kwargs:
                raise ValueError('Cannot set arg: {}'.format(arg))

        self.__is_optional = kwargs.pop('is_optional', True)
        if self.__is_optional:
            presence = Optional()
        else:
            resence = InputRequired()

        kwargs['validators'] = [presence]
        super(JournalistSelectField, self).__init__(*nargs, **kwargs)

    def populate_choices(self):
        if self.__is_optional:
            none_str = '({})'.format(gettext('unassigned'))
        else:
            none_str = ''

        # comparisons against self.data are to 'preselect' the current field
        # when this field is rendered in the UI
        journalists = Journalist.query.order_by(Journalist.username).all()
        choices = [('', none_str)]
        choices += [(j.uuid, j.username) for j in journalists]
        self.choices = choices


class NewUserForm(FlaskForm):
    username = TextField('username', validators=[
        InputRequired(message=gettext('This field is required.')),
        minimum_length_validation
    ])
    password = HiddenField('password')
    is_admin = BooleanField('is_admin')
    is_hotp = BooleanField('is_hotp')
    otp_secret = TextField('otp_secret', validators=[
        otp_secret_validation,
        Optional()
    ])


class ReplyForm(FlaskForm):
    message = TextAreaField(
        u'Message',
        id="content-area",
        validators=[
            InputRequired(message=gettext(
                'You cannot send an empty reply.')),
        ],
    )


class LogoForm(FlaskForm):
    logo = FileField(validators=[
        FileRequired(message=gettext('File required.')),
        FileAllowed(['png'],
                    message=gettext("You can only upload PNG image files."))
    ])


class ChangeSourceAssignmentForm(FlaskForm):

    journalist_uuid = JournalistSelectField(label='Assigned Journalist')
