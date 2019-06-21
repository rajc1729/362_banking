from flask import Flask, render_template, redirect, url_for,session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField,TextAreaField,BooleanField,RadioField,IntegerField,FloatField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import time
import datetime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'

base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(base_dir,'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):

    id = db.Column(db.Integer ,primary_key=True, autoincrement = True)
    username = db.Column(db.String(15), unique=True)
    name=db.Column(db.String(15))
    gender=db.Column(db.String(7))
    address=db.Column(db.String(130))
    city=db.Column(db.String(100))
    state=db.Column(db.String(80))
    zipcode=db.Column(db.String(80))
    date_of_birth=db.Column(db.Date)
    phone_number=db.Column(db.String(15))
    security_question=db.Column(db.String(150))
    security_question_answer=db.Column(db.String(150))

    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Account(db.Model):
    account_id=db.Column(db.Integer , db.ForeignKey('user.id'), primary_key=True,autoincrement = True)
    balance=db.Column(db.Float)




class Transaction(db.Model):
    transfer_id= db.Column(db.Integer ,primary_key=True, autoincrement = True)
    account_id=db.Column(db.Integer,db.ForeignKey('account.account_id'))
    amount=db.Column(db.Float)
    balance=db.Column(db.Float)
    time=db.Column(db.DateTime)
    type=db.Column(db.String(30))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    name = StringField('name', validators=[InputRequired(), Length(min=2, max=60)])
    gender = RadioField('gender', choices = [('male','Male'),('female','Female'),('other','Other')], validators=[InputRequired()])
    address=TextAreaField("Address",validators=[InputRequired(), Length(min=4, max=130)])
    city=StringField("city",validators=[InputRequired(), Length(min=2, max=100)])
    state=StringField("state",validators=[InputRequired(), Length(min=2, max=80)])
    zipcode=StringField("zip-code",validators=[InputRequired(), Length(min=2, max=80)])
    date_of_birth=DateField("Date of Birth",validators=[InputRequired()], format='%m/%d/%y')
    phone_number=StringField("Phone No.",validators=[InputRequired(), Length(min=4, max=15)])
    security_question=StringField("Security question",validators=[InputRequired(), Length(min=4, max=150)])
    security_question_answer=StringField("Security question answer",validators=[InputRequired(), Length(min=4, max=150)])

    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class DepositForm(FlaskForm):
    amount_deposit = FloatField('Deposit amount', validators=[InputRequired()])
    deposit=SubmitField("Deposit")


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data,name=form.name.data, email=form.email.data, gender=form.gender.data,address=form.address.data,city=form.city.data,state=form.state.data,zipcode=form.zipcode.data,date_of_birth=form.date_of_birth.data,phone_number=form.phone_number.data,security_question=form.security_question.data,security_question_answer=form.security_question_answer.data ,password=hashed_password)
        new_account=Account(balance=0.0)
        #db.create_all()

        db.session.add(new_user)
        db.session.add(new_account)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.filter_by(username=current_user.username).first()
    return render_template('dashboard.html', user_name=current_user.username,name=user.name,address=user.address,city=user.city,state=user.state,zipcode=user.zipcode,phone=user.phone_number )

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():

    form=DepositForm()
    user = User.query.filter_by(username=current_user.username).first()
    account = Account.query.filter_by(account_id=user.id).first()
    if form.validate_on_submit():
        #user_amount=form.amount_deposit.data
        #print(user_amount)
        new_transaction=Transaction(account_id=user.id, amount=form.amount_deposit.data, balance=float((account.balance)+form.amount_deposit.data) , time=datetime.datetime.now(), type="Deposit")
        account.balance=((account.balance)+form.amount_deposit.data)
        db.create_all()
        db.session.add(new_transaction)
        db.session.commit()
        return '<h1>New depost made!</h1>'

    return render_template('deposit.html', form=form )
    #return '<h1> deposit!</h1>'

@app.route('/withdraw')
@login_required
def withdraw():

    #return render_template('withdraw.html',  )
    return '<h1> withdraw!</h1>'

@app.route('/transfer')
@login_required
def transfer():

    #return render_template('transfer.html',  )
    return '<h1> transfer!</h1>'


@app.route('/appointment')
@login_required
def appointment():

    #return render_template('appointment.html',  )
    return '<h1> appointment!</h1>'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
