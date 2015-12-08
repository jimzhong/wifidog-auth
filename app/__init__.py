#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import logging
from binascii import hexlify
from datetime import datetime

from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.wtf import Form

basedir = os.path.abspath(os.path.dirname(__file__))
#logging.basicConfig(filename="auth.log", level=logging.DEBUG)
#logging.info("BaseDir is " + basedir)

app = Flask(__name__)
app.config['SECRET_KEY'] = "KEYKEY"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

from .views import *
from .models import User

def db_setup():
    db.drop_all()
    db.create_all()
    admin = User("zhong", "jimzhong", "test@test.com", admin=True)
    #free = User("test", "testtest", "test@test.cn", quota=5)
    db.session.add(admin)
    #db.session.add(free)
    db.session.commit()



