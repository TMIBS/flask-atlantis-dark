# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import Flask, app, render_template
from flask_login import LoginManager
from flask_oidc import OpenIDConnect
from importlib import import_module
from jinja2 import PackageLoader
from apps.authentication import models
from .home.routes import blueprint as home_blueprint
import os

login_manager = LoginManager()
oidc = OpenIDConnect()

def register_extensions(app):
    print(os.getcwd())
    login_manager.init_app(app)
    oidc.init_app(app)
    print("LoginManager and OIDC initialized with app")
    models.init_models(app, login_manager)
    print("Models initialized with app")

def register_blueprints(app):
    for module_name in ('authentication', 'home'):
        module = import_module('apps.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)

def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)
    # Use the PackageLoader
    #app.jinja_loader = PackageLoader('apps')
    app.register_blueprint(home_blueprint, url_prefix='/')
    register_extensions(app)
    register_blueprints(app)
    return app




