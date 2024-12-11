from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, send
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Post, WatchParty
from forms import LoginForm, RegisterForm, PostForm, WatchPartyForm

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
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
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(content=form.content.data, is_public=form.is_public.data, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!')
    posts = Post.query.filter_by(is_public=True).all()
    return render_template('dashboard.html', user=current_user, form=form, posts=posts)

@app.route('/watch-party', methods=['GET', 'POST'])
@login_required
def watch_party():
    form = WatchPartyForm()
    if form.validate_on_submit():
        party = WatchParty(name=form.name.data, video_url=form.video_url.data, host=current_user)
        db.session.add(party)
        db.session.commit()
        flash('Watch party created!')
        return redirect(url_for('dashboard'))
    return render_template('watch_party.html', form=form)

# SocketIO Events for Real-Time Chat
@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)
    send(f"{current_user.username} has joined the room.", to=room)

@socketio.on('leave')
def handle_leave(data):
    room = data['room']
    leave_room(room)
    send(f"{current_user.username} has left the room.", to=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    message = data['message']
    send(f"{current_user.username}: {message}", to=room)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")
    socketio.run(app, debug=True)
