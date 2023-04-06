from flask_wtf import FlaskForm
from wtforms import EmailField, StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, email_validator, Email
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Email(message="Invalid email")])
    name = StringField(label="Name", validators=[DataRequired()])
    password = PasswordField(label="password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Email(message="Invalid email")])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class CommentForm(FlaskForm): 
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Post Comment")
