from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileAllowed

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    avatar = FileField('Avatar', validators=[FileAllowed(['jpg', 'png'], 'Only JPG/PNG allowed!')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    title = StringField('Task Title', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Task Description')
    submit = SubmitField('Add Task')

class PostForm(FlaskForm):
    title = StringField('Post Title', validators=[DataRequired(), Length(min=2, max=100)])
    content = TextAreaField('Post Content', validators=[DataRequired()])
    submit = SubmitField('Create Post')
class ProfileForm(FlaskForm):
    avatar = FileField('Avatar', validators=[FileAllowed(['jpg', 'png'], 'Only JPG/PNG allowed!')])
    submit = SubmitField('Update Avatar')
