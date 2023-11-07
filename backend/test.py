from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from datetime import timedelta
from flask_jwt_extended import get_jwt
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps
from datetime import datetime
from datetime import timedelta
from datetime import timezone

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = '9h02MDVJUgU9VkcNS4xsb8zEnnNqXznx'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root_password@mariadb/coffee_chat_db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)



users_roles = {"user": True, "modo": False, "admin": False}
modos_roles = {"user": True, "modo": True, "admin": False}
admins_roles = {"user": True, "modo": True, "admin": True}

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP)
    pseudo = db.Column(db.String(255))

class ChatMessage(db.Model):
    __tablename__ = 'chat'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255))
    pseudo = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP)

class TokenBlocklist(db.Model):
    __tablename__ = 'TokenBlocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

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


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    pseudo = data.get('pseudo')
    password = data.get('password')
    user = User.query.filter_by(pseudo=pseudo).first()
    if user:
        if bcrypt.check_password_hash(user.password_hash, password):
            if (pseudo=="matribuk"):
                access_token = create_access_token(identity=pseudo, additional_claims=admins_roles)
                return jsonify(access_token=access_token), 201
            else:
                access_token = create_access_token(identity=pseudo, additional_claims=users_roles)
                return jsonify(access_token=access_token), 201
        else:
            return jsonify(message=f"Identifiant ou Mot de passe incorrect"), 401
    return jsonify(message=f"Identifiant ou Mot de passe incorrect"), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    pseudo = data.get('pseudo')
    existing_user = User.query.filter_by(pseudo=pseudo).first()
    if existing_user:
        return jsonify(message=f"Ce pseudonyme est déjà pris"), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, password_hash=password_hash, pseudo=pseudo)
    db.session.add(new_user)
    db.session.commit()

    if (pseudo=="matribuk"):
        access_token = create_access_token(identity=pseudo, additional_claims=admins_roles)
    else:
        access_token = create_access_token(identity=pseudo, additional_claims=users_roles)
    return jsonify(access_token=access_token)

@app.route("/logout", methods=["DELETE"])
@jwt_required()
@role_required("user")
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg=f"Logout sucessfullely")

@app.route("/blacklist", methods=["GET"])
@jwt_required()
@role_required("modo")
def protected():
    tokens = TokenBlocklist.query.all()
    token_data = [{'token': token.jti, 'created_at': token.created_at} for token in tokens]
    return jsonify(token_data)


@app.route('/users', methods=['GET'])
@jwt_required()
@role_required("admin")
def get_users():
    users = User.query.all()
    user_data = [{'pseudo': user.pseudo, 'created_at': user.created_at} for user in users]
    return jsonify(users=user_data)

@app.route('/users', methods=['DELETE'])
@jwt_required()
@role_required("user")
def delete_user():
    data = request.get_json()
    pseudo = data.get('pseudo')
    user_password = data.get('password')
    user = User.query.filter_by(pseudo=pseudo).first()

    if user:

        if bcrypt.check_password_hash(user.password_hash, user_password):
            jti = get_jwt()["jti"]
            now = datetime.now(timezone.utc)
            db.session.delete(user)
            db.session.add(TokenBlocklist(jti=jti, created_at=now))
            db.session.commit()
            return jsonify(message=f"Utilisateur supprimé avec succès"), 200
        else:
            return jsonify(message=f"Mot de passe incorrect"), 401
    else:
        return jsonify(message=f"Utilisateur non trouvé"), 404

@app.route('/chat', methods=['GET'])
@jwt_required()
@role_required("user")
def get_chat_messages():
    chat_messages = ChatMessage.query.all()
    chat_data = [{'text': message.text, 'pseudo': message.pseudo, 'created_at': message.created_at} for message in chat_messages]
    return jsonify(chat=chat_data)

@app.route('/chat', methods=['POST'])
@jwt_required()
@role_required("user")
def add_chat_message():
    data = request.get_json()
    pseudo = data.get('pseudo')
    user_password = data.get('password')
    message_text = data.get('text')
    user = User.query.filter_by(pseudo=pseudo).first()

    if user:
        if bcrypt.check_password_hash(user.password_hash, user_password):
            new_message = ChatMessage(text=message_text, pseudo=pseudo)
            db.session.add(new_message)
            db.session.commit()
            return jsonify(message=f"Message ajouté au chat avec succès"), 201
        else:
            return jsonify(message=f"Mot de passe incorrect"), 401
    else:
        return jsonify(message=f"Utilisateur non trouvé"), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5042)
