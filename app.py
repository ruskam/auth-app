from flask import Flask, render_template, flash, redirect, url_for, session, logging, request

from flask_mysqldb import MySQL
from functools import wraps

from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'webdev'
app.config['MYSQL_DB'] = 'android_app_users'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cursor = mysql.connection.cursor()
        cursor.execute("insert into users(name, email, username, password) values (%s, %s, %s, %s)",
                       (name, email, username, password))
        mysql.connection.commit()

        cursor.close()

        flash('Done! Registered', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_attempt = request.form['password']

        cursor = mysql.connection.cursor()
        result = cursor.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cursor.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_attempt, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('download'))

            else:
                error = "Invalid login"
                return render_template('login.html', error=error)

            cursor.close()
        else:
            error = "Username not found"
            return render_template('login.html', error=error)
    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorised access. Please, login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/download')
@is_logged_in
def download():
    return render_template('download.html')

if __name__ == '__main__':
    
    # Start the app in the debugging mode
    app.run(debug=True)
