#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import logging
import datetime
import wtforms
from flask import render_template, g, request, abort, redirect, session, url_for, flash, json, jsonify
from flask.ext.login import login_user, logout_user, login_required, current_user

from .forms import LoginForm, RegisterForm, ChangePasswordForm
from .zupassport import check_passport
from .models import User, Log
from . import app, db


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        studentid = form.studentid.data.strip()
        password = form.password.data.strip()
        exist_user = User.query.filter_by(username=studentid).first()
        if exist_user:
            flash("User {} already exists. You should login rather than sign up.".format(studentid), "danger")
            return redirect("login")
        try:
            logging.debug("Validating {} against zuinfo".format(studentid))
            valid = check_passport(studentid, password)
        except IOError as e:
            flash(str(e), "danger")
            return abort(500)
        if(valid):
            new_user = User(studentid, password, studentid+"@zju.edu.cn")
            db.session.add(new_user)
            db.session.commit()
            flash("Registration is successful. You can login now.", "info")
            return redirect("login")
        else:
            flash("Your credentials are invalid.", "danger")
    return render_template("register.html", form=form)


@app.route("/auth")
def auth():

    def make_reply(code):
        return "Auth: {}".format(code)

    AUTH_DENIED = 0
    AUTH_ALLOWED = 1
    AUTH_VALIDATION = 5
    AUTH_ERROR = -1

    ua = request.headers.get('User-Agent')
    if ua and 'wifidog' not in ua.lower():
        return abort(404)

    stage = request.args.get('stage').lower()
    ipaddr = request.args.get('ip').lower()
    mac = request.args.get('mac').lower()
    token = request.args.get('token').lower()
    incoming = int(request.args.get('incoming'))
    outgoing = int(request.args.get('outgoing'))

    token = Log.query.filter_by(token=token, mac=mac, ipaddr=ipaddr, valid=True).first()
    if token:
        token.update_counters(incoming, outgoing)
        if token.user.quota_exceeded or not token.user.enabled:
            return make_reply(AUTH_DENIED)
        return make_reply(AUTH_ALLOWED)

    return make_reply(AUTH_DENIED)


@app.route("/prelogin")
def prelogin():
    # session.clear()
    session['gw_address'] = request.args.get("gw_address")
    session['gw_port'] = request.args.get("gw_port")
    session['url'] = request.args.get("url")
    session['gw_id'] = request.args.get("gw_id")
    session['ip'] = request.args.get('ip')
    session['mac'] = request.args.get('mac')
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            if user.enabled:
                user.ping()
                login_user(user)
                if user.quota_exceeded:
                    flash("You exceeded your quota of {} MBytes per month. If you need more, please contact Jim.".format(user.quota), "warning")
                    return redirect(url_for('dashboard'))
                if session.get("gw_id") is None:
                    #If the user is not redirected by router, go to the dashboard, do not assign wifi token
                    return redirect(url_for('dashboard'))
                else:
                    #Only assign token if login via wifidog
                    new_token = user.assign_token(session.get('ip'), session.get('mac'))
                    gateway_auth_url = "http://{}:{}/wifidog/auth?token={}".format(session['gw_address'], session['gw_port'], new_token)
                    del session['gw_id']
                    session['wifitoken'] = new_token
                    return redirect(gateway_auth_url)
            else:
                flash("This account is disabled.", "warning")
        else:
            flash('Invalid username or password.', "warning")
    return render_template('login.html', form=form)


@app.route("/cpw", methods=['GET', 'POST'])
@login_required
def changepw():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        oldpw = form.old_password.data
        newpw = form.password.data
        if not current_user.verify_password(oldpw):
            flash("Current password does not match!", "danger")
        elif oldpw == newpw:
            flash("New password and old password are the same. Do nothing.", "warning")
        else:
            current_user.password = newpw
            flash("Password changed.", "success")
            return redirect(url_for('dashboard'))
    return render_template("changepw.html", form=form, user=current_user)


@app.route('/dashboard')
@login_required
def dashboard():
    now = datetime.datetime.now()
    day_list = range(1, now.day+1);
    download = {}
    upload = {}
    for l in current_user.logs:
        if l.create_timestamp.month == now.month:
            download[l.create_timestamp.day] = download.get(l.create_timestamp.day, 0) + l.incoming
            upload[l.create_timestamp.day] = upload.get(l.create_timestamp.day, 0) + l.outgoing
    dlist = []
    ulist = []
    for day in day_list:
        dlist.append(download.get(day, 0))
        ulist.append(upload.get(day, 0))
    return render_template("dashboard.html", user=current_user, logs=current_user.logs[:10], xaxis=list(day_list), ulist=ulist, dlist=dlist)


@app.route("/admin")
@login_required
def admin():
    if current_user.is_admin:
        return render_template("admin.html", users=User.query.all(), user=current_user)
    return abort(401)

@app.route("/profile/<int:uid>")
@login_required
def profile(uid):
    if current_user.is_admin or current_user.uid == uid:
        return render_template("profile.html", user=User.query.get(uid))
    return abort(401)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    # if 'wifitoken' in session:
    #     t = Log.query.filter_by(token=session['wifitoken']).first()
    #     t.make_invalid()
    #     session.clear()
    #     flash("You have logged out. You will be disconnected soon.", 'warning')
    # else:
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/disconnect/<int:uid>")
@login_required
def disconnect(uid):
    if current_user.is_admin or current_user.uid == uid:
        user = User.query.get(uid)
        if not user:
            return 'No such user'
        if user.online:
            user.disconnect()
            flash("{} disconnected successfully.".format(user.username), "success")
        else:
            flash("{} do not have active connections.".format(user.username), "info")
        return redirect(url_for("dashboard"))
    return abort(401)


@app.route('/ping')
def ping():
    INACTIVE_THRESHOLD = 100
    active_logs = Log.query.filter_by(valid=True).all()
    cut = datetime.datetime.now() - datetime.timedelta(seconds=INACTIVE_THRESHOLD)
    #If wifidog did not report a token in INACTIVE_THRESHOLD seconds, the token will be marked invalid
    for l in active_logs:
        if l.update_timestamp < cut:
            l.make_invalid()
    return 'Pong'


@app.route("/message")
def message():
    return render_template("message.html")


@app.route("/exceed")
def exceed():
    flash("You have exceeded you quota. Your access to Internet is restricted.", "warning")
    return render_template("message.html")


@app.route("/lottery")
def lottery():
    return "TODO"


@app.route("/api/stat")
@login_required
def api_stat():
    return json.dumps({"data_usage":current_user.data_usage, "quota":current_user.quota})


@app.route("/api/logs/<int:logid>")
@login_required
def api_logs(logid):
    l = Log.query.get(logid)
    if l:
        return jsonify(logid=l.logid, day=l.create_timestamp.day, download=l.incoming, upload=l.outgoing)
    return abort(404)


@app.route("/api/chart")
@login_required
def api_chart():
    now = datetime.datetime.now()
    t = [(l.logid, l.create_timestamp.day, l.incoming, l.outgoing) for l in current_user.logs if l.create_timestamp.month == now.month]
    return json.dumps(t)