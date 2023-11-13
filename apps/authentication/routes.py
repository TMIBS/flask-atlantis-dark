# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import render_template, redirect, request, url_for, session
from flask_oidc import OpenIDConnect
from apps.authentication import blueprint
from apps import login_manager
import jwt

oidc = OpenIDConnect()

@blueprint.route('/')
def route_default():
    if not oidc.user_loggedin:
        return redirect(url_for('authentication_blueprint.login'))
    else:
        # Get user's information
        user_info = oidc.user_getinfo(['name','preferred_username', 'email', 'groups'])
        user_full_name = user_info.get('name', 'Unknown User')
        # Get user's roles
        access_token_info = oidc.get_access_token()  # Example method, adjust based on your setup
        decoded_token = jwt.decode(access_token_info, options={"verify_signature": False})
        user_roles = decoded_token.get('realm_access', {}).get('roles', [])
        session['user_roles'] = user_roles
        user_groups = user_info.get('groups', [])
        session['user_groups'] = user_groups
        session['fullname'] = user_full_name
        first_name = user_full_name.split(' ')[0]
        session['first_name'] = first_name
        initials = "".join([word[0] for word in user_full_name.split()][:2]).upper()  # This will get the first two initials
        session['initials'] = initials
        print(initials)
        # You can store user_info in a session or do other operations as required
        next_url = session.pop('next_url', None)
        print("next_url: ", next_url)
        if next_url:
            return redirect(next_url)  # Redirect to the originally requested URL
        else:
            return redirect(url_for('home_blueprint.index'))

@blueprint.route('/oidc/callback')
def oidc_callback():
    print("Hello3")
    if oidc.user_loggedin:
        user_info = oidc.user_getinfo(['preferred_username', 'email', 'groups'])
        access_token_info = oidc.get_access_token()  # Example method, adjust based on your setup
        user_roles = oidc.user_getfield('realm_access').get('roles', [])
        session['user_roles'] = user_roles
        print(user_roles)
        user_groups = user_info.get('groups', [])
        session['user_groups'] = user_groups
        # You can store user_info in a session or do other operations as required
        next_url = session.pop('next_url', None)
        print("next_url: ", next_url)
        if next_url:
            return redirect(next_url)  # Redirect to the originally requested URL
        else:
            return redirect(url_for('home_blueprint.index'))
    else:
        return redirect(url_for('authentication_blueprint.login'))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    print("Accessed login route")
    if not oidc.user_loggedin:
        return redirect(url_for('authentication_blueprint.login'))
    else:
        return redirect(url_for('home_blueprint.index'))

@blueprint.route('/logout')
def logout():
    print("before:" + oidc.user_loggedin)
    oidc.logout()
    print("after:" + oidc.user_loggedin)
    return redirect(url_for('authentication_blueprint.login'))


# Errors

#@login_manager.unauthorized_handler
#def unauthorized_handler():
#    return render_template('home/page-403.html'), 403

@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403

@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404

@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500
