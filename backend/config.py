from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql://root:root_password@mariadb/coffee_chat_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'the-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
