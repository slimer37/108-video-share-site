from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, URLField
from wtforms.validators import DataRequired, Email, Length, URL

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
    is_public = BooleanField('Public Post')
    submit = SubmitField('Create Post')

class WatchPartyForm(FlaskForm):
    name = StringField('Party Name', validators=[DataRequired()])
    video_url = URLField('Video URL', validators=[DataRequired(), URL()])
    is_private = BooleanField('Private Room')  # Toggle for privacy
    description = TextAreaField('Room Description', validators=[Length(max=500)])
    submit = SubmitField('Create Watch Party')
