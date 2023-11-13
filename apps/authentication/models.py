# Description: Authentication models
""" from apps import login_manager
from apps import oidc
from flask_login import UserMixin

@login_manager.user_loader
def user_loader(user_id):
     # Fetch user details from OIDC
    user_info = oidc.user_getinfo(['preferred_username', 'email'])
    username = user_info['preferred_username']
    email = user_info['email']

    # You'd normally query your database here for the user
    # For the sake of illustration, let's use a dummy user object
    class DummyUser(UserMixin):
        def __init__(self, id, username, email):
            self.id = id
            self.username = username
            self.email = email

    return DummyUser(user_id, username, email)

@login_manager.request_loader
def request_loader(_):
    # This is not necessary with OIDC.
    pass """
from flask_oidc import OpenIDConnect
from flask_login import UserMixin

oidc = OpenIDConnect()

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

def init_models(app, login_manager):
    @login_manager.user_loader
    def load_user(user_id):
        print("load_user called with user_id:", user_id)
        if oidc.user_loggedin:
            print("User is logged in with OIDC")
            user_info = oidc.user_getinfo(['preferred_username', 'email'])
            username = user_info['preferred_username']
            email = user_info['email']
            print("Returning user object with username:", username)
            return User(user_id, username, email)
        return None

    @login_manager.request_loader
    def load_user_from_request(req):
        auth_header = req.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        else:
            token = req.args.get('token')
    
        if token:
            user_info = oidc.user_getinfo(['preferred_username', 'email'], token=token)
            if user_info:
                username = user_info['preferred_username']
                email = user_info['email']
                return User(token, username, email)
        return None


