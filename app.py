import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Post, WatchParty, FriendRequest
from forms import LoginForm, RegisterForm, PostForm, WatchPartyForm
from admin_routes import admin_bp, block_banned

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the uploads folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle image uploads
@app.route("/upload-image", methods=["POST"])
@login_required
def upload_image():
    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["image"]

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        image_url = f"/static/uploads/{filename}"
        return jsonify({"image_url": image_url}), 200

    return jsonify({"error": "Invalid file type"}), 400

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register the admin blueprint
app.register_blueprint(admin_bp)

# Seed database with initial data
def seed_data():
    """Seed the database with initial data."""
    db.drop_all()
    db.create_all()

    # Create an admin user
    admin_user = User(
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('admin123', method='pbkdf2:sha256'),
        is_admin=True
    )
    db.session.add(admin_user)

    # Create sample users
    user1 = User(
        username='testuser1',
        email='testuser1@example.com',
        password=generate_password_hash('password1', method='pbkdf2:sha256')
    )
    user2 = User(
        username='testuser2',
        email='testuser2@example.com',
        password=generate_password_hash('password2', method='pbkdf2:sha256')
    )
    db.session.add_all([user1, user2])

    # Commit seeded data to the database
    db.session.commit()
    print("Database seeded with initial data!")

# Middleware to check if user is banned
@app.before_request
def check_banned_status():
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        flash('Your account is banned. Please contact support.', 'danger')
        return redirect(url_for('login'))

# Routes for authentication
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.is_banned:
                flash('Your account is banned. Please contact support.', 'danger')
                return redirect(url_for('login'))
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin.admin_page'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard route for posts
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@block_banned
def dashboard():
    form = PostForm()
    if form.validate_on_submit():
        # Get the content (HTML) from the hidden textarea
        content = request.form['content']
        is_public = form.is_public.data

        # Save the post
        new_post = Post(
            content=content,
            is_public=is_public,
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!')

    posts = Post.query.filter_by(is_public=True).all()
    return render_template('dashboard.html', user=current_user, form=form, posts=posts)

# Watch Party route
@app.route('/watch-party', methods=['GET', 'POST'])
@login_required
@block_banned
def watch_party():
    form = WatchPartyForm()
    party = WatchParty.query.filter_by(host_id=current_user.id).order_by(WatchParty.id.desc()).first()

    if form.validate_on_submit():
        party = WatchParty(
            name=form.name.data,
            video_url=form.video_url.data,
            host=current_user,
            is_private=form.is_private.data,
            description=form.description.data
        )
        db.session.add(party)
        db.session.commit()
        flash('Watch party created!')
        return redirect(url_for('watch_party'))

    if not party:
        party = WatchParty(name="New Watch Party", video_url="", host=current_user)
        db.session.add(party)
        db.session.commit()

    return render_template('watch_party.html', form=form, party=party)

# Friends route
@app.route('/friends')
@login_required
@block_banned
def friends():
    friends_list = current_user.friends
    all_users = User.query.filter(User.id != current_user.id, User.is_admin == False).all()
    return render_template('friends.html', friends=friends_list, all_users=all_users)

@app.route('/available-rooms')
@login_required
def available_rooms():
    search_query = request.args.get('search', '')
    friends_only = request.args.get('friends_only', False)

    query = WatchParty.query.join(User).filter(User.username.ilike(f"%{search_query}%"))

    if friends_only:
        query = query.filter(User.id.in_([friend.id for friend in current_user.friends]))

    rooms = query.all()

    return render_template('available_rooms.html', rooms=rooms)


# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
        print("Database initialized successfully!")
    socketio.run(app, debug=True)
