FROM mariadb:latest

ENV MYSQL_ROOT_PASSWORD=root_password
ENV MYSQL_DATABASE=coffee_chat_db

COPY init.sql /docker-entrypoint-initdb.d/
