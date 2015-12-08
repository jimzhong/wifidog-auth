#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import logging

from binascii import hexlify
from datetime import datetime

from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, login_manager

DEFAULT_QUOTA = 2000

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.Unicode(64), unique=True, index=True)
    password_hash = db.Column(db.Unicode(128))
    email = db.Column(db.Unicode(128))
    join_time = db.Column(db.DateTime, default=datetime.now)
    last_seen = db.Column(db.DateTime)
    logs = db.relationship("Log", backref='user', order_by='desc(Log.logid)')

    #Controls
    quota = db.Column(db.Integer, default=DEFAULT_QUOTA)
    is_admin = db.Column(db.Boolean)
    enabled = db.Column(db.Boolean)

    def get_id(self):
        return self.uid

    def __init__(self, username, plaintext_password, email, admin=False, enabled=True, quota = DEFAULT_QUOTA):
        self.username = username
        self.password = plaintext_password
        self.email = email
        self.is_admin = admin
        self.enabled = enabled
        self.quota = quota

    def __repr__(self):
        return "<User {}>".format(self.username)

    def __str__(self):
        return "{} {} {}".format(self.username, self.ipaddr, self.token)

    def verify_password(self, plain_text_password):
        return check_password_hash(self.password_hash, plain_text_password)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = generate_password_hash(plain_text_password)

    @property
    def data_usage(self):
        now = datetime.now()
        usage = 0
        for l in self.logs:
            if l.create_timestamp.month == now.month:
                usage += l.incoming + l.outgoing
            # elif not l.valid:
            #     #Remove all logs of previous month
            #     db.session.delete(l)
        return usage

    @property
    def quota_exceeded(self):
        return self.data_usage > self.quota

    def assign_token(self, ip, mac):
        '''
        Assign new wifidog token to a user, while invalidating all previous tokens
        Return ascii encoded token as a unicode string
        '''
        #Void all previous valid tokens assigned to this user
        active_tokens = Log.query.filter_by(uid=self.uid, valid=True)
        for token in active_tokens:
            token.make_invalid()
        #Generate a new token for this user
        new_token = Log(self, ip, mac)
        db.session.add(new_token)
        logging.debug(new_token)
        return new_token.token

    def ping(self):
        self.last_seen = datetime.now()
        db.session.add(self)

    @property
    def online(self):
        if self.logs:
            return self.logs[0].valid
        return False

    def disconnect(self):
        if self.logs:
            self.logs[0].make_invalid()


class Log(db.Model):
    __tablename__ = 'logs'
    logid = db.Column(db.Integer, primary_key=True)
    create_timestamp = db.Column(db.DateTime, default=datetime.now)
    update_timestamp = db.Column(db.DateTime, default=datetime.now)
    token = db.Column(db.Unicode(128))
    ipaddr = db.Column(db.Unicode(64))
    mac = db.Column(db.Unicode(32))
    incoming = db.Column(db.Integer, default=0)
    outgoing = db.Column(db.Integer, default=0)
    valid = db.Column(db.Boolean, default=True)
    uid = db.Column(db.Integer, db.ForeignKey('users.uid'))

    @staticmethod
    def gentoken():
        return hexlify(os.urandom(20)).decode().lower()

    @property
    def start_time_string(self):
        return self.create_timestamp.ctime()

    @property
    def stop_time_string(self):
        if self.valid:
            return "Current Session"
        return self.update_timestamp.ctime()

    def __init__(self, user, ip, mac):
        self.uid = user.uid
        self.ipaddr = ip
        self.mac = mac
        self.token = self.gentoken()

    def update_counters(self, incoming, outgoing):
        #assert(self.valid)
        self.incoming = int(incoming) // 1048576    #Convert to MBytes
        self.outgoing = int(outgoing) // 1048576
        self.update_timestamp = datetime.now()

    def make_invalid(self):
        logging.debug("Marking {} as invalid".format(self.token))
        self.valid = False

    def __repr__(self):
        return "<Token {} for uid {} Valid={}>".format(self.token, self.uid, self.valid)

