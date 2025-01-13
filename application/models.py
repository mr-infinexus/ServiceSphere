from app import db
from datetime import datetime, timezone, timedelta
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False, unique=True)
    password_hashed = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum("admin", "customer", "professional"), nullable=False)
    status = db.Column(db.Enum("pending", "verified", "blocked"), nullable=False)
    fullname = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(256), nullable=False)
    pincode = db.Column(db.Integer, nullable=False)
    contact_number = db.Column(db.Integer, nullable=False)
    service_type = db.Column(db.Integer, db.ForeignKey("services.id"), nullable=True)
    experience = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone(timedelta(hours=5, minutes=30))))
    provider = db.relationship("Service", back_populates="provided_by", uselist=False)
    customer_requests = db.relationship("ServiceRequest", back_populates="customer", foreign_keys="ServiceRequest.customer_id")
    professional_requests = db.relationship("ServiceRequest", back_populates="professional", foreign_keys="ServiceRequest.professional_id")


class Service(db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    time_required = db.Column(db.Integer, nullable=False)  # in minutes
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone(timedelta(hours=5, minutes=30))))
    provided_by = db.relationship("User", back_populates="provider", cascade="all, delete-orphan")


class ServiceRequest(db.Model):
    __tablename__ = "service_requests"
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    time_of_request = db.Column(db.DateTime, default=datetime.now(timezone(timedelta(hours=5, minutes=30))))
    time_of_completion = db.Column(db.DateTime)
    service_status = db.Column(db.Enum("requested", "accepted", "rejected", "closed"), nullable=False)
    task = db.Column(db.Text)
    service = db.relationship("Service", backref="service_requests", lazy=True)
    customer = db.relationship("User", back_populates="customer_requests", foreign_keys=[customer_id])
    professional = db.relationship("User", back_populates="professional_requests", foreign_keys=[professional_id])


class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey("service_requests.id", ondelete="CASCADE"), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone(timedelta(hours=5, minutes=30))))
