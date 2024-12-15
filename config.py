import os

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///socialvisor.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuration for file uploads
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')  # Path to the uploads folder
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}           # Allowed file extensions
