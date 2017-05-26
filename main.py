import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, session, render_template, request, redirect, config, url_for
import os
import MySQLdb
import hashlib
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(12)
app.config.from_pyfile('config.cfg')

@app.before_request
def make_session_permanent():
	app.permanent = True
	app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/')
def index():
	if 'uid' in session:
		format_name = "%s, %s %s., %s" % (session['lname'],session['fname'],session['mi'],session['title'])
		app.logger.error(format_name)
		return render_template('index.html',format=format_name)
	else:
		return redirect(url_for('login'))
	

@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		in_user = request.form['username']
		in_pass = request.form['password']
		db = MySQLdb.connect(app.config['DB_HOST'],app.config['DB_USER'],app.config['DB_PASS'],app.config['DB_NAME'])
		c = db.cursor()
		sql = "SELECT salt FROM {} WHERE username=%s".format(app.config['TABLE_LOGINS'])
		app.logger.error(sql)
		c.execute(sql,[in_user])
		if c.rowcount == 1:
			salt = c.fetchone()[0]
			app.logger.error(salt)
			hashed = sha1_salt(in_pass,str(salt))
			c = db.cursor()	
			sql = "SELECT * FROM {} WHERE username=%s AND password=%s".format(app.config['TABLE_LOGINS'])
			app.logger.error(sql)
			c.execute(sql,[in_user,str(hashed)])
			app.logger.error(sql)
			if c.rowcount == 1:
				results = c.fetchall()
				for row in results:
					session['uid'] = row[0]
					session['username'] = row[1]
					session['fname'] = row[4]
					session['lname'] = row[5]
					session['mi'] = row[6]
					session['title'] = row[7]

				return redirect(url_for('index'))
			else:
				return render_template('login.html',user=in_user,error="Incorrect password. Please note that too many attempts will result in your account being locked.")
		else:
			return render_template('login.html',user=in_user,error="User not found. Please try again.")
	elif request.method == 'GET':
		if 'uid' in session:
			return redirect(url_for('index'))
		else:
			return render_template('login.html')
	

if __name__ == "__main__":
	app.run(debug=True,host='0.0.0.0')

def sha1_salt(passwd,salt):
	return hashlib.sha1(str(passwd).encode('utf-8')+str(salt).encode('utf-8')).hexdigest()


