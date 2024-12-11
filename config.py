import os

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///socialvisor.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
