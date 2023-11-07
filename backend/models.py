from extensions import db, jwt

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

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