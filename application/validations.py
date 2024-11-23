from flask_wtf import FlaskForm
from application.models import Service
from wtforms import IntegerField, DecimalField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import InputRequired, Length, NumberRange, Optional


class LoginForm(FlaskForm):
    username = StringField("Username :", validators=[InputRequired(), Length(min=4, max=32)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField("Password :", validators=[InputRequired(), Length(min=8, max=32)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class CustomerRegistrationForm(FlaskForm):
    username = StringField("Username :", validators=[InputRequired(), Length(min=4, max=32)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField("Password :", validators=[InputRequired(), Length(min=8, max=32)],
                             render_kw={"placeholder": "Password"})
    fullname = StringField("Full Name :", validators=[InputRequired(), Length(min=3, max=64)],
                           render_kw={"placeholder": "Full Name"})
    address = StringField("Address :", validators=[
                          InputRequired(), Length(min=3, max=256)])
    pincode = IntegerField("Pincode :", validators=[
                           InputRequired(), NumberRange(min=100000, max=999999)])
    contact_number = IntegerField("Contact Number :", validators=[
                                  InputRequired(), NumberRange(min=1000000000, max=9999999999)])
    submit = SubmitField("Register as Customer")


class ProfessionalRegistrationForm(FlaskForm):
    username = StringField("Username :", validators=[InputRequired(), Length(min=4, max=32)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField("Password :", validators=[InputRequired(), Length(min=8, max=32)],
                             render_kw={"placeholder": "Password"})
    fullname = StringField("Full Name :", validators=[
                           InputRequired(), Length(min=3, max=64)])
    service_type = SelectField("Service Name :",
                               choices=[], validators=[InputRequired()])
    experience = IntegerField("Experience (in Years) :", validators=[
                              InputRequired(), NumberRange(min=0, max=60)])
    address = StringField("Address :", validators=[
                          InputRequired(), Length(min=3, max=256)])
    pincode = IntegerField("Pincode :", validators=[
                           InputRequired(), NumberRange(min=100000, max=999999)])
    contact_number = IntegerField("Contact Number :", validators=[
                                  InputRequired(), NumberRange(min=1000000000, max=9999999999)])
    submit = SubmitField("Register as Professional")

    def __init__(self, *args, **kwargs):
        super(ProfessionalRegistrationForm, self).__init__(*args, **kwargs)
        self.service_type.choices = [
            ("", "Choose an option")] + [(service.id, service.name) for service in Service.query.all()]


class EditServiceForm(FlaskForm):
    name = StringField("Service Name :", validators=[
                       InputRequired(), Length(min=2, max=100)])
    price = DecimalField("Price :", places=2, rounding=None, validators=[
                         InputRequired(), NumberRange(min=0, message="Price must be positive")])
    time_required = IntegerField("Time Required (minutes) :",
                                 validators=[InputRequired(), NumberRange(
                                     min=0, message="Time required must be non-negative")]
                                 )
    description = StringField("Description (if any) :", validators=[Optional()])
    submit = SubmitField("Submit")


class BookServiceForm(FlaskForm):
    service_id = StringField("Service ID :", render_kw={"readonly": True})
    professional_id = StringField(
        "Professional ID :", render_kw={"readonly": True})
    task = StringField('Task :', validators=[
                       InputRequired(), Length(min=2, max=100)])
    submit = SubmitField('Submit')


class RemarksForm(FlaskForm):
    service_id = StringField("Service ID :", render_kw={"readonly": True})
    professional_id = StringField(
        "Professional ID :", render_kw={"readonly": True})
    rating = SelectField("Service Rating :",
                         choices=[(0, "Select a Rating"),
                                  (5, "★★★★★"), (4, "★★★★☆"), (3, "★★★☆☆"), (2, "★★☆☆☆"), (1, "★☆☆☆☆")],
                         coerce=int, validators=[InputRequired(), NumberRange(min=1, max=5)])
    remarks = StringField("Remarks (if any) :", validators=[Optional()])
    submit = SubmitField('Submit Review')


class EditProfileForm(FlaskForm):
    fullname = StringField("Full Name", validators=[
                           InputRequired(), Length(min=3, max=64)])
    address = StringField("Address", validators=[
                          InputRequired(), Length(min=3, max=256)])
    pincode = IntegerField("Pincode", validators=[
                           InputRequired(), NumberRange(min=100000, max=999999)])
    contact_number = IntegerField("Contact No", validators=[
                                  InputRequired(), NumberRange(min=1000000000, max=9999999999)])
    submit = SubmitField("Update Profile")
