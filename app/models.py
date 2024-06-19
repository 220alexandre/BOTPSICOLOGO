from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.dialects.mysql import LONGTEXT
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    plan = db.Column(db.String(50), nullable=False, default='free')
    token_limit = db.Column(db.Integer, nullable=False, default=0)
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    company = db.relationship('Company', back_populates='users')
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    user_limit = db.Column(db.Integer, nullable=False)
    token_limit = db.Column(db.Integer, nullable=False)
    current_token_usage = db.Column(db.Integer, nullable=False, default=0)
    users = db.relationship('User', back_populates='company', cascade="all, delete-orphan")
    employees = db.relationship('Employee', back_populates='company', cascade="all, delete-orphan")
    custom_plans = db.relationship('CustomPlan', back_populates='company', cascade="all, delete-orphan")

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    user_limit = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)
    company = db.relationship('Company', back_populates='employees')

class CustomPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    tokens_per_user = db.Column(db.Integer, nullable=False)
    company = db.relationship('Company', back_populates='custom_plans')

class FileContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    content = db.Column(LONGTEXT, nullable=False)
