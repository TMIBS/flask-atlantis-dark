# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
import secrets

class Config(object):
    OIDC_CLIENT_ID = 'tvm-local-dashboard'
    OIDC_CLIENT_SECRET = 'YuzPpQrhRYvl3FFI9zq6Wnv5Apgp2NzG'
    SECRET_KEY = secrets.token_hex(16)
    OIDC_ISSUER = 'https://keycloak-test.kdo.de/auth/realms/KDO'
    OIDC_SCOPES = ['openid', 'email']
    OIDC_COOKIE_SECURE = False  # Set to True for production  
    OIDC_CLIENT_SECRETS = {
    "web": {
        "client_id": "tvm-local-dashboard",
        "client_secret": "YuzPpQrhRYvl3FFI9zq6Wnv5Apgp2NzG",
        "auth_uri": "https://keycloak-test.kdo.de/auth/realms/KDO/auth",
        "token_uri": "https://keycloak-test.kdo.de/auth/realms/KDO/token",
        "issuer": "https://keycloak-test.kdo.de/auth/realms/KDO",
        "redirect_uris": [
            "http://localhost:5000/oidc/callback"
        ]
    }
}
class ProductionConfig(Config):
    DEBUG = False

    # Security
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

class DebugConfig(Config):
    DEBUG = True

# Load all possible configurations
config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig
}