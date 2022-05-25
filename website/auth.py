# keep in mind that import is just  a fancy word for include in Python
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User # import/include the User mentioned in models.py so we can use the script here
from werkzeug.security import generate_password_hash, check_password_hash # so se can protect our passwords in the db
from . import db
from flask_login import login_fresh, login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route("/login", methods = ['GET', 'POST'])
def login():
    # check if the form is working
    # data = request.form
    # print(data)
    
    # now let's verify signed in users
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # check is user exist
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='warning')
        else:
            flash('Email does not exist.', category='warning')
    return render_template("login.html", user = current_user)

@auth.route('/logout')
@login_required # decorator -> don't access this function unless logged in
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route("/sign-up", methods = ['GET', 'POST'])
def sign_up():
    # data = request.form
    # print(data)
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # check if dude already signed up
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Account already exist!', category='warning')
        # validate input
        elif len(email) < 4:
            flash('email must be greater than 4 chars.', category = 'warning')
        elif len(firstname) < 2:
            flash('firstname must be greater than 1 chars.', category = 'warning')
        elif password != confirm_password:
            flash('passwords must be same!', category = 'warning')
        elif len(password) < 4:
            flash('password must be greater than 3 chars.', category = 'warning') 
        else:
            # add user to DB
            new_user = User(email=email, firstname=firstname, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Saved!', category = 'success')
            return redirect(url_for('views.home')) # views.home is better than /home, so that if you change it in views, it won't affect here

    return render_template("sign_up.html", user = current_user)
