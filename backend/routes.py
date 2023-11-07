from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from models import User, ChatMessage, TokenBlocklist
from extensions import bcrypt
from datetime import datetime, timezone
from auth_utils import users_roles, modos_roles, admins_roles, role_required
from extensions import db

app_bp = Blueprint('app', __name__)



@app_bp.route("/login", methods=["POST"])
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

@app_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    pseudo = data.get('pseudo')
    existing_user = User.query.filter_by(pseudo=pseudo).first()
    now = datetime.now(timezone.utc)
    if existing_user:
        return jsonify(message=f"Ce pseudonyme est déjà pris"), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, password_hash=password_hash, pseudo=pseudo, created_at= now)
    db.session.add(new_user)
    db.session.commit()

    if (pseudo=="matribuk"):
        access_token = create_access_token(identity=pseudo, additional_claims=admins_roles)
    else:
        access_token = create_access_token(identity=pseudo, additional_claims=users_roles)
    return jsonify(access_token=access_token)

@app_bp.route("/logout", methods=["DELETE"])
@jwt_required()
@role_required("user")
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg=f"Logout sucessfullely")

@app_bp.route("/blacklist", methods=["GET"])
@jwt_required()
@role_required("modo")
def protected():
    tokens = TokenBlocklist.query.all()
    token_data = [{'token': token.jti, 'created_at': token.created_at} for token in tokens]
    return jsonify(token_data)


@app_bp.route('/users', methods=['GET'])
@jwt_required()
@role_required("admin")
def get_users():
    users = User.query.all()
    user_data = [{'pseudo': user.pseudo, 'created_at': user.created_at} for user in users]
    return jsonify(users=user_data)

@app_bp.route('/users', methods=['DELETE'])
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

@app_bp.route('/chat', methods=['GET'])
@jwt_required()
@role_required("user")
def get_chat_messages():
    chat_messages = ChatMessage.query.all()
    chat_data = [{'text': message.text, 'pseudo': message.pseudo, 'created_at': message.created_at} for message in chat_messages]
    return jsonify(chat=chat_data)

@app_bp.route('/chat', methods=['POST'])
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