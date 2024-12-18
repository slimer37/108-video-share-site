from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Column, Text
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

# Association table for friends
friends_table = db.Table(
    'friends',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    profile_photo = db.Column(db.String(300), nullable=True)  # Path to profile photo
    posts = db.relationship('Post', backref='user', lazy=True)
    watch_parties = db.relationship('WatchParty', backref='host', lazy=True)
    friends = db.relationship('User', secondary=friends_table,
                              primaryjoin=id == friends_table.c.user_id,
                              secondaryjoin=id == friends_table.c.friend_id,
                              backref='friend_of')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id',
                                        backref='receiver', lazy=True)
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id',
                                    backref='sender', lazy=True)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # Possible statuses: 'pending', 'accepted', 'rejected'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reactions = db.Column(JSON, default={}) 

class WatchParty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    video_url = db.Column(db.String(300), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)  # Privacy setting
    description = db.Column(db.String(500), nullable=True)  # Room description

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')


class ChatGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    members = db.relationship('User', secondary='group_members', backref='groups')


group_members = db.Table(
    'group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('chat_group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)  # Correct field name
    timestamp = db.Column(db.DateTime, default=db.func.now())

    sender = db.relationship('User', backref='group_messages')
    group = db.relationship('ChatGroup', backref='messages')
    