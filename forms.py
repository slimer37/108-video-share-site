from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, URLField
from wtforms.validators import DataRequired, Email, EqualTo, Length, URL, ValidationError
from models import User

class ChangeUsernameForm(FlaskForm):
    new_username = StringField('New Username', validators=[
        DataRequired(),
        Length(min=3, max=150)
    ])
    submit = SubmitField('Update Username')

    def validate_new_username(self, new_username):
        user = User.query.filter_by(username=new_username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one.')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        'Current Password',
        validators=[DataRequired(), Length(min=8)]
    )
    new_password = PasswordField(
        'New Password',
        validators=[DataRequired(), Length(min=8)]
    )
    confirm_new_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(),
            EqualTo('new_password', message="Passwords must match"),
        ]
    )
    submit = SubmitField('Change Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    is_public = BooleanField('Public Post', default=True)
    submit = SubmitField('Create Post')

class WatchPartyForm(FlaskForm):
    name = StringField('Party Name', validators=[DataRequired()])
    video_url = URLField('Video URL', validators=[DataRequired(), URL()])
    is_private = BooleanField('Private Room')  # Toggle for privacy
    description = TextAreaField('Room Description', validators=[Length(max=500)])
    submit = SubmitField('Create Watch Party')
