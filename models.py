from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.mysql import LONGTEXT

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    plan = db.Column(db.String(50), nullable=False, default='free')
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    company = db.relationship('Company', back_populates='users')

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

    users = db.relationship('User', back_populates='company')
    employees = db.relationship('Employee', back_populates='company')
    custom_plans = db.relationship('CustomPlan', order_by='CustomPlan.id', back_populates='company')

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Adicionado
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    user_limit = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)

    company = db.relationship('Company', back_populates='employees')
    user = db.relationship('User', back_populates='employee')  # Adicionado


class FileContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    content = db.Column(LONGTEXT, nullable=False)

class CustomPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    tokens_per_user = db.Column(db.Integer, nullable=False)

    company = db.relationship('Company', back_populates='custom_plans')
