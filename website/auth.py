from flask import Blueprint, render_template, request, flash, redirect, url_for
from .modules import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('You are successfully logged in', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Wrong password', category='error')
        else:
            flash('No such user found', category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(name) < 2:
            flash('Name must by greater than 3 chars', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1) < 7:
            flash('Password greater than 7 chars', category='error')
        else:
            new_user = User(email=email, first_name=name, password=generate_password_hash(password1, method='sha256'))
            user = User.query.filter_by(email=email).first()
            if not user:
                db.session.add(new_user)
                db.session.commit()
                flash('Account created', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            flash('This account already exists', category='error')

    return render_template("signUp.html", user=current_user)
