from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, login_required, logout_user, current_user
from app import db, bcrypt
from app.models import User, Task, Post
from app.forms import RegistrationForm, LoginForm, TaskForm, PostForm
from werkzeug.utils import secure_filename
import os
from functools import wraps
from PIL import Image
from app.forms import ProfileForm 

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

# Blueprint
main = Blueprint('main', __name__)
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@main.before_request
def before_request():
    current_app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file selected', 'danger')
        return redirect(request.referrer)

    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.referrer)

    if file and allowed_file(file.filename):
        filename = secure_filename(f"{current_user.id}_{file.filename}")
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        # Kiểm tra kích thước file
        file.seek(0, os.SEEK_END)  # Duyệt đến cuối file để lấy kích thước
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        if file_size > MAX_FILE_SIZE:
            flash('File too large (max 2MB)', 'danger')
            return redirect(request.referrer)

        # Lưu file
        file.save(file_path)

        # Resize ảnh nếu cần (200x200px)
        try:
            img = Image.open(file_path)
            img.thumbnail((200, 200))
            img.save(file_path)
        except Exception as e:
            flash('Error processing image', 'danger')
            return redirect(request.referrer)

        # Cập nhật avatar trong database
        current_user.avatar = filename
        db.session.commit()

        flash('Avatar updated successfully!', 'success')

    return redirect(request.referrer)

# ======================== AUTHENTICATION ========================

@main.route("/")
@main.route("/home")
def home():
    return render_template('base.html')

@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_password)

        db.session.add(user)
        db.session.commit()
        flash("Account created successfully!", "success")
        return redirect(url_for("main.login"))
    return render_template("register.html", form=form)

@main.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.is_active and user.check_password(form.password.data):

            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('main.login'))

# ======================== TASK MANAGEMENT ========================

@main.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks():
    form = TaskForm()
    if form.validate_on_submit():
        new_task = Task(title=form.title.data, description=form.description.data, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added!', 'success')
        return redirect(url_for('main.tasks'))
    # Chỉ admin hoặc chính chủ mới xem được task
    if current_user.role == 'admin':
        user_tasks = Task.query.all()
    else:
        user_tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template("tasks.html", form=form, tasks=user_tasks)

@main.route("/edit_task/<int:task_id>", methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.tasks'))

    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        db.session.commit()
        flash("Task updated!", "success")
        return redirect(url_for('main.tasks'))

    return render_template("edit_task.html", form=form, task=task)

@main.route("/toggle_task/<int:task_id>", methods=["POST"])
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.tasks'))
    
    task.completed = not task.completed
    db.session.commit()
    flash("Task status updated!", "success")
    return redirect(url_for('main.tasks'))

@main.route("/delete_task/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.tasks'))
    
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted!", "success")
    return redirect(url_for('main.tasks'))

# ======================== POST MANAGEMENT ========================

@main.route("/posts", methods=['GET', 'POST'])
@login_required
def posts():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title=form.title.data, content=form.content.data, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Post added!', 'success')
        return redirect(url_for('main.posts'))

    user_posts = Post.query.all()  # Ai cũng có thể xem post
    return render_template("posts.html", form=form, posts=user_posts)

@main.route("/delete_post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.posts'))
    
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted!", "success")
    return redirect(url_for('main.posts'))
@main.route("/edit_post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.posts'))

    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash("Post updated!", "success")
        return redirect(url_for('main.posts'))

    return render_template("edit_post.html", form=form, post=post)
# ======================== ADMIN MANAGEMENT ========================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Access denied!", "danger")
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin.html', users=users)


@admin_bp.route('/lock/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def lock_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot lock an admin!", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    
    user.active_status = False
    db.session.commit()
    flash(f"User {user.username} locked!", "warning")
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/unlock/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.active_status = True
    db.session.commit()
    flash(f"User {user.username} unlocked!", "success")
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/delete/<int:user_id>', methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot delete an admin!", "danger")
        return redirect(url_for('admin.admin_dashboard'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted!", "danger")
    return redirect(url_for('admin.admin_dashboard'))
@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()  # Tạo instance form
    return render_template('profile.html', form=form)  # Truyền form vào template
