from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, send, emit
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

    # Fetch the latest watch party for the current user
    party = WatchParty.query.filter_by(host_id=current_user.id).order_by(WatchParty.id.desc()).first()

    if form.validate_on_submit():
        # Create and save a new watch party
        party = WatchParty(
            name=form.name.data,
            video_url=form.video_url.data,
            host=current_user,
            is_private=form.is_private.data,
            description=form.description.data
        )
        db.session.add(party)
        db.session.commit()  # Ensure the party is committed to the database

        flash('Watch party created!')
        return redirect(url_for('watch_party'))

    # If no party exists, create a placeholder
    if not party:
        party = WatchParty(name="New Watch Party", video_url="", host=current_user)
        db.session.add(party)
        db.session.commit()  # Commit the placeholder to generate an ID

    return render_template('watch_party.html', form=form, party=party)

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

@socketio.on('hostRoom')
def handle_host_room(data):
    room = data['room']
    is_private = data['isPrivate']
    watch_party = WatchParty.query.get(room)
    if watch_party:
        watch_party.is_private = is_private
        db.session.commit()
        emit('roomHosted', {'message': f"Room hosted as {'Private' if is_private else 'Public'}."}, broadcast=True)

@socketio.on('screenShare')
def handle_screen_share(data):
    room = data['room']
    track = data['track']
    emit('screenShare', {'track': track}, room=room, include_self=False)

@app.route('/friends')
@login_required
def friends():
    friends_list = current_user.friends
    all_users = User.query.filter(User.id != current_user.id).all()
    return render_template('friends.html', friends=friends_list, all_users=all_users)

@app.route('/add-friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    friend = User.query.get_or_404(friend_id)
    if friend not in current_user.friends:
        current_user.friends.append(friend)
        db.session.commit()
        flash(f'You are now friends with {friend.username}!')
    else:
        flash(f'You are already friends with {friend.username}.')
    return redirect(url_for('friends'))

@app.route('/remove-friend/<int:user_id>', methods=['POST'])
@login_required
def remove_friend(user_id):
    friend = User.query.get(user_id)
    if friend in current_user.friends:
        current_user.friends.remove(friend)
        db.session.commit()
        flash(f'{friend.username} has been removed from your friends list.')
    return redirect(url_for('friends'))

@app.route('/join-room/<int:room_id>')
@login_required
def join_room_page(room_id):
    party = WatchParty.query.get_or_404(room_id)
    if party.is_private and current_user not in party.host.friends:
        flash('This room is private. Only friends can join.')
        return redirect(url_for('dashboard'))
    return render_template('watch_party.html', party=party)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")
    socketio.run(app, debug=True)