from flask import Flask, render_template, url_for,session,redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,DateTimeField ,DateField,TextAreaField,BooleanField,RadioField,IntegerField,FloatField, SubmitField
from wtforms_components import TimeField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import time
import datetime
from sqlalchemy.ext.declarative import declarative_base
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from flask import g



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
admin=Admin(app)


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

class Make_an_appointment(db.Model):
    appointment_id=db.Column(db.Integer ,primary_key=True, autoincrement = True)
    appointment_account_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    appointment_date=db.Column(db.Date)
    appointment_time=db.Column(db.Time)
    appointment_location=db.Column(db.String(60))
    about_what=db.Column(db.String(100))


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

class WithdrawForm(FlaskForm):
    amount_withdraw = FloatField('Withdraw amount', validators=[InputRequired()])
    withdraw=SubmitField("Withdraw")

class TransferForm(FlaskForm):
    amount_transfer = FloatField('Transfer amount', validators=[InputRequired()])
    account_number=IntegerField('Account number', validators=[InputRequired()])
    transfer=SubmitField("Transfer")


class AppointmentForm(FlaskForm):
    appointment_date=DateField("Date" ,validators=[InputRequired()], format='%m/%d/%y')
    appointment_time=TimeField("Time" ,validators=[InputRequired()])
    appointment_location=StringField('location', validators=[InputRequired(), Length(min=2, max=60)])
    about_what=StringField('About what', validators=[InputRequired(), Length(min=2, max=100)])
    schedule=SubmitField("Schedule")

class ResetForm(FlaskForm):
    reset_username = StringField('Enter username', validators=[InputRequired(), Length(min=4, max=15)])
    next=SubmitField("Next")


class SecurityForm(FlaskForm):
    question_answer=StringField("Security question answer",validators=[InputRequired(), Length(min=4, max=150)])

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New password', validators=[InputRequired(), Length(min=8, max=80)])


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
    account = Account.query.filter_by(account_id=user.id).first()
    all_transactions= Transaction.query.filter_by(account_id=user.id)
    return render_template('dashboard.html', all_transactions=all_transactions,id=user.id ,user_name=current_user.username,name=user.name,address=user.address,city=user.city,state=user.state,zipcode=user.zipcode,phone=user.phone_number,balance=account.balance )

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

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    form=WithdrawForm()
    user = User.query.filter_by(username=current_user.username).first()
    account = Account.query.filter_by(account_id=user.id).first()
    if form.validate_on_submit():
        if (form.amount_withdraw.data)<=account.balance:
            new_transaction=Transaction(account_id=user.id, amount=(-(form.amount_withdraw.data)), balance=float((account.balance)-form.amount_withdraw.data) , time=datetime.datetime.now(), type="Withdraw")
            account.balance=((account.balance)-form.amount_withdraw.data)

            db.session.add(new_transaction)
            db.session.commit()
            return '<h1>New withdraw made!</h1>'
        else:
            return '<h1>Insufficient balance!</h1>'

    return render_template('withdraw.html', form=form )
    #return '<h1> withdraw!</h1>'

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    form=TransferForm()
    user_sender = User.query.filter_by(username=current_user.username).first()
    account_sender = Account.query.filter_by(account_id=user_sender.id).first()
    if form.validate_on_submit():

        user_recieve = User.query.filter_by(id=form.account_number.data).first()
        if user_recieve:
            account_recieve = Account.query.filter_by(account_id=user_recieve.id).first()
            if (form.amount_transfer.data)<=account_sender.balance:

                new_transaction_debit=Transaction(account_id=user_sender.id, amount=(-(form.amount_transfer.data)), balance=float((account_sender.balance)-form.amount_transfer.data) , time=datetime.datetime.now(), type=("Transfer to, {}." .format(user_recieve.name)) )
                new_transaction_credit=Transaction(account_id=user_recieve.id, amount=((form.amount_transfer.data)), balance=float((account_recieve.balance)+form.amount_transfer.data) , time=datetime.datetime.now(), type=("Transfer from, {}." .format(user_sender.name))  )
                account_sender.balance=((account_sender.balance)-form.amount_transfer.data)
                account_recieve.balance=((account_recieve.balance)+form.amount_transfer.data)

                db.session.add(new_transaction_debit)
                db.session.add(new_transaction_credit)
                db.session.commit()
                return '<h1>New transfer made!</h1>'
            else:
                return '<h1>Insufficient balance!</h1>'

        else:
            return '<h1>Invalid account number!</h1>'



    return render_template('transfer.html', form=form )

    #return render_template('transfer.html',  )
    #return '<h1> transfer!</h1>'


@app.route('/appointment', methods=['GET', 'POST'])
@login_required
def appointment():
    form=AppointmentForm()
    user = User.query.filter_by(username=current_user.username).first()
    all_appointment= Make_an_appointment.query.filter_by(appointment_account_id=user.id).first()
    if form.validate_on_submit():
        new_appointment=Make_an_appointment(appointment_account_id=user.id,appointment_date=form.appointment_date.data,appointment_time=form.appointment_time.data, appointment_location=form.appointment_location.data, about_what=form.about_what.data)
        db.session.add(new_appointment)
        db.session.commit()
        return '<h1>New appointment made!</h1>'


    return render_template('appointment.html',all_appointment=all_appointment , form=form  )
    #return '<h1> appointment!</h1>'




@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    form=ResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.reset_username.data).first()
        if user:
            session['forgot_user_name'] = (form.reset_username.data)

            return redirect(('security_question'))
        else:
            return '<h1>Invalid user!</h1>'

    return render_template('reset.html' , form=form   )

@app.route('/security_question', methods=['GET', 'POST'])
def reset_user_password():
    form=SecurityForm()
    forgot_user = session.get('forgot_user_name', None)
    user = User.query.filter_by(username=forgot_user).first()
    question_asked=user.security_question
    if form.validate_on_submit():
        que_answer=user.security_question_answer
        if (str(que_answer)==str(form.question_answer.data)):
            return redirect(url_for('reset_link'))
        else:
            return "<h1>Invalid answer!</h1>"

    return render_template('security_question.html' , question_asked=question_asked,form=form   )

@app.route('/reset_link', methods=['GET', 'POST'])
def reset_link():
    form=ResetPasswordForm()
    forgot_user = session.get('forgot_user_name', None)
    user = User.query.filter_by(username=forgot_user).first()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user.password=hashed_password
        db.session.commit()
        return "<h1>Password changed!</h1>"

    return render_template('reset_link.html' , form=form   )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
