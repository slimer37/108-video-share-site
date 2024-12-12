from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

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
    posts = db.relationship('Post', backref='user', lazy=True)
    watch_parties = db.relationship('WatchParty', backref='host', lazy=True)
    friends = db.relationship('User', secondary=friends_table,
                              primaryjoin=id == friends_table.c.user_id,
                              secondaryjoin=id == friends_table.c.friend_id,
                              backref='friend_of')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class WatchParty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    video_url = db.Column(db.String(300), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)  # Privacy setting
    description = db.Column(db.String(500), nullable=True)  # Room description
