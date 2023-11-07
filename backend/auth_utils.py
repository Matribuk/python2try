from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt, verify_jwt_in_request

users_roles = {"user": True, "modo": False, "admin": False}
modos_roles = {"user": True, "modo": True, "admin": False}
admins_roles = {"user": True, "modo": True, "admin": True}

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get(role, False):
                return fn(*args, **kwargs)
            else:
                return jsonify(msg=f"You are not allow to use this request"), 403
        return decorator
    return wrapper