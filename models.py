from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def to_dict(self):
        """Convert user object to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at,
            'first_name': self.first_name,
            'last_name': self.last_name
        }

class FacebookMarketingRequest(db.Model):
    __tablename__ = 'facebook_marketing_requests'

    id = db.Column(db.Integer, primary_key=True)
    page_name = db.Column(db.String(100), nullable=False)
    page_url = db.Column(db.String(200), nullable=False)
    campaign_objective = db.Column(db.String(100), nullable=False)
    target_audience = db.Column(db.String(200), nullable=True)
    budget = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class InstagramMarketingRequest(db.Model):
    __tablename__ = 'instagram_marketing_requests'

    id = db.Column(db.Integer, primary_key=True)
    page_name = db.Column(db.String(100), nullable=False)
    page_url = db.Column(db.String(200), nullable=False)
    campaign_objective = db.Column(db.String(100), nullable=False)
    target_audience = db.Column(db.String(200), nullable=True)
    budget = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class SnapchatMarketingRequest(db.Model):
    __tablename__ = 'snapchat_marketing_requests'

    id = db.Column(db.Integer, primary_key=True)
    page_name = db.Column(db.String(100), nullable=False)
    page_url = db.Column(db.String(200), nullable=False)
    campaign_objective = db.Column(db.String(100), nullable=False)
    target_audience = db.Column(db.String(200), nullable=True)
    budget = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class TiktokMarketingRequest(db.Model):
    __tablename__ = 'tiktok_marketing_requests'

    id = db.Column(db.Integer, primary_key=True)
    page_name = db.Column(db.String(100), nullable=False)
    page_url = db.Column(db.String(200), nullable=False)
    campaign_objective = db.Column(db.String(100), nullable=False)
    target_audience = db.Column(db.String(200), nullable=True)
    budget = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class RequestIDs(db.Model):
    __tablename__ = 'request_ids'

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    request_type = db.Column(db.Integer, nullable=False)

    user = db.relationship('User', backref='request_ids')
    def to_dict(self):
        """Convert request id object to dictionary."""
        return {
            'id': self.id,
            'request_id': self.request_id,
            'user_id': self.user_id,
            'request_type': self.request_type
        }

class Messages(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(800), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    request_id = db.Column(db.Integer, db.ForeignKey('request_ids.request_id'), nullable=True)
    user = db.relationship('User', backref='messages')
    request = db.relationship('RequestIDs', backref='messages')

    def to_dict(self):
        """Convert message object to dictionary."""
        return {
            'id': self.id,
            'message': self.message,
            'user_id': self.user_id,
            'created_at': self.created_at,
            'request_id': self.request_id
        }