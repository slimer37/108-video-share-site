import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Post, WatchParty, FriendRequest, DirectMessage, ChatGroup, GroupMessage
from forms import ChangePasswordForm, ChangeUsernameForm, LoginForm, RegisterForm, PostForm, WatchPartyForm
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

# File upload configuration
PROFILE_PHOTO_FOLDER = 'static/uploads/profile_photos'
POST_IMAGE_FOLDER = 'static/uploads/post_images'
app.config['PROFILE_PHOTO_FOLDER'] = PROFILE_PHOTO_FOLDER
app.config['POST_IMAGE_FOLDER'] = POST_IMAGE_FOLDER

os.makedirs(PROFILE_PHOTO_FOLDER, exist_ok=True)
os.makedirs(POST_IMAGE_FOLDER, exist_ok=True)

# Save profile photo helper
def save_profile_photo(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['PROFILE_PHOTO_FOLDER'], filename)
        file.save(filepath)
        return f"/static/uploads/profile_photos/{filename}"
    return None

@app.route('/upload-profile-photo', methods=['POST'])
@login_required
def upload_profile_photo():
    if 'profile_photo' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('account_settings'))

    file = request.files['profile_photo']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('account_settings'))

    file_url = save_profile_photo(file)
    if file_url:
        current_user.profile_photo = file_url
        db.session.commit()
        flash('Profile photo updated successfully!', 'success')
    else:
        flash('Invalid file type', 'danger')

    return redirect(url_for('account_settings'))


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

@app.route('/account-settings')
@login_required
def account_settings():
    return render_template('account_settings.html')

@app.route('/change-username', methods=['GET', 'POST'])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        # Update the username
        current_user.username = form.new_username.data
        db.session.commit()
        flash('Your username has been updated successfully!', 'success')
        return redirect(url_for('account_settings'))

    return render_template('change_username.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # Validate the current password
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # Update the password
        current_user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html', form=form)

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

    return render_template('watch_party.html', user=current_user, form=form, party=party)

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

# New event to notify users when screen sharing starts
@socketio.on('screenShareStarted')
def handle_screen_share_started(data):
    room = data['room']
    emit('screenShareStarted', {}, room=room, include_self=False)

# New event to notify users when screen sharing stops
@socketio.on('screenShareStopped')
def handle_screen_share_stopped(data):
    room = data['room']
    emit('screenShareStopped', {}, room=room, include_self=False)

@socketio.on('offer')
def handle_offer(data):
    room = data['room']
    offer = data['offer']
    emit('offer', {'offer': offer}, room=room, include_self=False)

@socketio.on('answer')
def handle_answer(data):
    room = data['room']
    answer = data['answer']
    emit('answer', {'answer': answer}, room=room, include_self=False)

@socketio.on('ice-candidate')
def handle_ice_candidate(data):
    room = data['room']
    candidate = data['candidate']
    emit('ice-candidate', {'candidate': candidate}, room=room, include_self=False)

@app.route('/friends')
@login_required
@block_banned
def friends():
    friends_list = current_user.friends
    all_users = User.query.filter(User.id != current_user.id, User.is_admin == False).all()
    return render_template('friends.html', friends=friends_list, all_users=all_users)
    # Exclude users who are already friends
    all_users = User.query.filter(User.id != current_user.id, ~User.friends.any(id=current_user.id)).all()
    return render_template('friends.html', friends=friends_list, all_users=all_users)

@app.route('/add-friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    if friend_id == current_user.id:
        flash("You cannot send a friend request to yourself.")
        return redirect(url_for('friends'))

    friend = User.query.get_or_404(friend_id)
    if friend in current_user.friends:
        flash(f'You are already friends with {friend.username}.')
        return redirect(url_for('friends'))

    existing_request = FriendRequest.query.filter_by(sender_id=current_user.id, receiver_id=friend_id).first()
    if existing_request:
        flash('Friend request already sent.')
        return redirect(url_for('friends'))

    friend_request = FriendRequest(sender_id=current_user.id, receiver_id=friend_id)
    db.session.add(friend_request)
    db.session.commit()
    flash(f'Friend request sent to {friend.username}.')

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


@app.route('/send-friend-request/<int:receiver_id>', methods=['POST'])
@login_required
def send_friend_request(receiver_id):
    receiver = User.query.get_or_404(receiver_id)

    # Prevent sending friend requests to admin users
    if receiver.is_admin:
        flash('You cannot send a friend request to an admin.')
        return redirect(url_for('friends'))

    existing_request = FriendRequest.query.filter_by(sender_id=current_user.id, receiver_id=receiver_id).first()

    if existing_request:
        flash('Friend request already sent.')
    else:
        friend_request = FriendRequest(sender_id=current_user.id, receiver_id=receiver_id)
        db.session.add(friend_request)
        db.session.commit()
        flash(f'Friend request sent to {receiver.username}.')

    return redirect(url_for('friends'))

@app.route('/accept-friend-request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)

    if friend_request.receiver_id == current_user.id:
        # Add each other as friends
        sender = User.query.get(friend_request.sender_id)
        current_user.friends.append(sender)
        db.session.delete(friend_request)
        db.session.commit()
        flash(f'You are now friends with {sender.username}.')
    else:
        flash('Invalid friend request.')

    return redirect(url_for('friends'))

@app.route('/reject-friend-request/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)

    if friend_request.receiver_id == current_user.id:
        db.session.delete(friend_request)
        db.session.commit()
        flash('Friend request rejected.')
    else:
        flash('Invalid friend request.')

    return redirect(url_for('friends'))

@app.route('/direct-messages')
@login_required
def direct_messages():
    friends_list = current_user.friends
    return render_template('direct_messages.html', friends=friends_list)


@app.route('/direct-messages/<int:friend_id>', methods=['GET', 'POST'])
@login_required
def chat_with_friend(friend_id):
    friend = User.query.get_or_404(friend_id)
    messages = DirectMessage.query.filter(
        ((DirectMessage.sender_id == current_user.id) & (DirectMessage.receiver_id == friend_id)) |
        ((DirectMessage.sender_id == friend_id) & (DirectMessage.receiver_id == current_user.id))
    ).order_by(DirectMessage.timestamp).all()

    if request.method == 'POST':
        message = request.form['message']
        new_message = DirectMessage(sender_id=current_user.id, receiver_id=friend_id, message=message)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('chat_with_friend', friend_id=friend_id))

    return render_template('chat_with_friend.html', friend=friend, messages=messages)


@app.route('/group-chats')
@login_required
def group_chats():
    groups = current_user.groups
    return render_template('group_chats.html', groups=groups)


@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def chat_with_group(group_id):
    group = ChatGroup.query.get_or_404(group_id)
    if current_user not in group.members:
        flash('You are not a member of this group.')
        return redirect(url_for('group_chats'))

    if request.method == 'POST':
        message = request.form['message']
        new_message = GroupMessage(group_id=group_id, sender_id=current_user.id, message=message)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('chat_with_group', group_id=group_id))

    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp.asc()).all()
    return render_template('chat_with_group.html', group=group, messages=messages)

@app.route('/create-group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        group_name = request.form['name']
        friend_ids = request.form.getlist('friend_ids')

        # Create the new group and add the current user
        new_group = ChatGroup(name=group_name)
        new_group.members.append(current_user)

        # Add selected friends to the group
        for friend_id in friend_ids:
            friend = User.query.get(friend_id)
            if friend:
                new_group.members.append(friend)

        db.session.add(new_group)
        db.session.commit()
        flash(f'Group "{group_name}" created successfully.')

        return redirect(url_for('group_chats'))

    friends_list = current_user.friends
    return render_template('create_group.html', friends=friends_list)

@app.route('/invite-to-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def invite_to_group(group_id):
    group = ChatGroup.query.get_or_404(group_id)
    
    # Ensure the current user is a member of the group
    if current_user not in group.members:
        flash('You are not authorized to invite friends to this group.')
        return redirect(url_for('group_chats'))

    if request.method == 'POST':
        friend_ids = request.form.getlist('friend_ids')
        for friend_id in friend_ids:
            friend = User.query.get(friend_id)
            if friend and friend not in group.members:
                group.members.append(friend)

        db.session.commit()
        flash('Friends have been invited to the group.')
        return redirect(url_for('chat_with_group', group_id=group.id))

    # Get the list of friends who are not yet in the group
    friends_not_in_group = [friend for friend in current_user.friends if friend not in group.members]
    
    return render_template('invite_to_group.html', group=group, friends=friends_not_in_group)

@app.route('/join-room/<int:room_id>')
@login_required
def join_room_page(room_id):
    party = WatchParty.query.get_or_404(room_id)
    if party.is_private and current_user not in party.host.friends:
        flash('This room is private. Only friends can join.')
        return redirect(url_for('available_rooms'))
    return render_template('watch_party.html', user=current_user, party=party)

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

@app.route('/add-reaction/<int:post_id>', methods=['POST'])
@login_required
def add_reaction(post_id):
    data = request.get_json()
    emoji = data.get("emoji")

    post = Post.query.get_or_404(post_id)

    # Initialize or update reactions dictionary
    if not post.reactions:
        post.reactions = {}
    post.reactions[emoji] = post.reactions.get(emoji, 0) + 1

    db.session.commit()
    return jsonify(reactions=post.reactions)


# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
        print("Database initialized successfully!")
    socketio.run(app, debug=True)
