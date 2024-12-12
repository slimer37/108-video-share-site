from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from models import db, User
from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

# Define the blueprint
admin_bp = Blueprint('admin', __name__, template_folder='templates')

#Added ban feature
def block_banned(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_banned:
            flash('Your account is banned. Please contact support.', 'danger')
            return redirect(url_for('logout'))
        return f(*args, **kwargs)
    return decorated_function


# Admin Dashboard Route
@admin_bp.route('/admin', methods=['GET'])
@login_required
def admin_page():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin.html', users=users)

# Ban User Route
@admin_bp.route('/admin/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('You cannot ban another admin.', 'danger')
        return redirect(url_for('admin.admin_page'))

    user.is_banned = True
    db.session.commit()
    flash(f'User {user.username} has been banned.', 'success')
    return redirect(url_for('admin.admin_page'))

# Unban User Route
@admin_bp.route('/admin/unban_user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if not user.is_banned:
        flash('User is not banned.', 'info')
        return redirect(url_for('admin.admin_page'))

    user.is_banned = False
    db.session.commit()
    flash(f'User {user.username} has been unbanned.', 'success')
    return redirect(url_for('admin.admin_page'))

# Delete User Route
@admin_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('You cannot delete another admin.', 'danger')
        return redirect(url_for('admin.admin_page'))

    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} has been deleted.', 'success')
    return redirect(url_for('admin.admin_page'))
