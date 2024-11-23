from app import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False, unique=True)
    password_hashed = db.Column(db.String(256), nullable=False)
    role = db.Column(
        db.Enum("admin", "customer", "professional"), nullable=False)
    status = db.Column(
        db.Enum("pending", "verified", "blocked"), nullable=False)
    fullname = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(256), nullable=False)
    pincode = db.Column(db.Integer, nullable=False)
    contact_number = db.Column(db.Integer, nullable=False)
    service_type = db.Column(
        db.Integer, db.ForeignKey("services.id"), nullable=True)
    experience = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class Service(db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    time_required = db.Column(db.Integer, nullable=False)  # in minutes
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class ServiceRequest(db.Model):
    __tablename__ = "service_requests"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(
        db.Integer, db.ForeignKey("services.id"), nullable=False)
    customer_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    professional_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    time_of_request = db.Column(
        db.DateTime, default=db.func.current_timestamp())
    time_of_completion = db.Column(db.DateTime)
    service_status = db.Column(
        db.Enum("requested", "accepted", "rejected", "closed"), nullable=False)
    task = db.Column(db.Text)


class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(
        db.Integer, db.ForeignKey("service_requests.id"), nullable=False)
    professional_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    customer_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
