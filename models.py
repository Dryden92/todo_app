from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(128))
    tasks = db.relationship('Task', backref='author', lazy='dynamic')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    deadline = db.Column(db.Date)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
