import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie, Morsel
import json
import datetime
import re
import mysql.connector
from jinja2 import Environment, FileSystemLoader, select_autoescape
from urllib.parse import parse_qs
from utils import *
import os
import secrets
from urllib.parse import urlparse, parse_qs


class FormCRUD:
    """CRUD"""
    @staticmethod
    def form_page_post(handler, cursor, cnx, env):
        """Method for posting"""
        template = env.get_template("index.html")
        output = template.render(errors={}, data={}, user={})

        content_length = int(handler.headers["Content-Length"])
        post_data = handler.rfile.read(content_length)
        print(post_data)
        data = parse_qs(post_data.decode("utf-8"))
        data = {key: value[0] for key, value in data.items() if value}


        print(post_data, data)

        errors = Form.validate(data)

        # Cookies!
        secret_key = secrets.token_urlsafe(16)

        # Set the cookie with error information and secret key
        cookie_value = json.dumps({"errors": errors, "secret": secret_key})
        print(cookie_value)

        user = User.generate_user()
        rawc = handler.headers.get("Cookie")
        cookie_data = SimpleCookie()

        if errors:
            output = template.render(errors=errors, data=json.dumps(data), user={})
            handler.send_response(400)  # Bad Request
            handler.send_cors_headers()
            cookie_data["errors"] = cookie_value
            # handler.send_header("Set-Cookie", f"errors={cookie_value}; Path=/; HttpOnly")  # Expires in session
            handler.send_header("Set-Cookie", cookie_data.output(header=""))
            handler.send_header("Content-Type", "text/html")
            handler.end_headers()
            handler.wfile.write(output.encode("utf-8"))
            return


        form = Form.from_dict(data)
        # Create user and add it to session
        # (If it's not already created)
        if rawc is not None:
            cookie_data.load(rawc)

        if "user" not in cookie_data:
            user_orm = UserORM(user, cursor, cnx).insert_db()
        else:
            user = User(cookie_data["username"],
                        cookie_data["password"])



        output = template.render(errors=errors["errors"], data=data, user=user)

        user_id = UserORM(user, cursor, cnx).get_id()[0]
        print(user_id, user)
        FormORM(form, cursor, cnx).insert_db(user_id)

        expires = datetime.datetime.utcnow() + datetime.timedelta(days=360) # expires in 30 days

        cookie_data["session"] = str(uuid.uuid4())
        cookie_data["session"]["path"] = "/"
        cookie_data["session"]["expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")

        cookie_data["errors"] = json.dumps(errors)
        cookie_data["errors"]["path"] = "/"

        cookie_data["user"] = json.dumps(user.to_dict())
        cookie_data["user"]["path"] = "/"

        cookie_data["data"] = json.dumps(form.to_dict())
        cookie_data["data"]["path"] = "/"
        # Send a response back to the client
        handler.send_response(200)
        handler.send_cors_headers()
        # Set cookie
        print(cookie_data.output(header=""))
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Set-Cookie", cookie_data["session"].output(header=""))
        handler.send_header("Set-Cookie", cookie_data["error"].output(header=""))
        handler.send_header("Set-Cookie", cookie_data["user"].output(header=""))
        handler.send_header("Set-Cookie", cookie_data["data"].output(header=""))
        handler.end_headers()

        handler.wfile.write(output.encode("utf-8"))

    @staticmethod
    def form_page_get(handler, env):
        """get page of form"""

        handler.send_response(200)
        handler.send_cors_headers()

        cookie_raw = handler.headers.get("Cookie")
        cookie = SimpleCookie()
        if cookie_raw is not None:
            cookie.load(cookie_raw)

        data = get_cookie_data(cookie)
        user = data["user"]
        errors = data["errors"]
        data = data["data"]
        # Jinja
        template = env.get_template("index.html")
        output = template.render(errors=errors, data=data, user=user)

        # Send response
        handler.send_header("Content-Type", "text/html")
        handler.end_headers()
        handler.wfile.write(output.encode("utf-8"))

    @staticmethod
    def login_page_get(handler, env):
        """get login page form"""
        handler.send_response(200)
        handler.send_cors_headers()

        cookie_raw = handler.headers.get("Cookie")
        cookie = SimpleCookie()
        if cookie_raw is not None:
            cookie.load(cookie_raw)

        rec = get_cookie_data(cookie)
        user = rec.get("user")
        print(bool(user))
        template = env.get_template("login.html")
        output = None
        if bool(user):
            # Already
            output = template.render(logined=True, user=user, login_errors = {})
        else:
            # Not Yet
            output = template.render(logined=False, user={}, login_errors = {})


        handler.send_header("Content-Type", "text/html")
        handler.end_headers()
        handler.wfile.write(output.encode("utf-8"))

    @staticmethod
    def login_page_post(handler, cursor, cnx, env):
        """LOGIN"""
        cookie_data = SimpleCookie()
        template = env.get_template("login.html")
        content_length = int(handler.headers["Content-Length"])
        post_data = handler.rfile.read(content_length)
        print(post_data)
        data = parse_qs(post_data.decode("utf-8"))
        data = {key: value[0] for key, value in data.items() if value}

        login_errors = {}
        print(data)
        if "username" in data and "password" in data:
            user = User(data["username"], data["password"])
            if User.check_in_db(user, cursor, cnx):
                expires = datetime.datetime.utcnow() + datetime.timedelta(days=360) # expires in 30 days
                cookie_data["session"] = str(uuid.uuid4())
                cookie_data["session"]["path"] = "/"
                cookie_data["session"]["expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")

                cookie_data["user"] = json.dumps(user.to_dict())
                cookie_data["user"]["path"] = "/"

                handler.send_response(200)
                handler.send_cors_headers()
                handler.send_header("Content-Type", "text/html")
                handler.send_header("Set-Cookie", cookie_data["session"].output(header=""))
                handler.send_header("Set-Cookie", cookie_data["user"].output(header=""))
                handler.end_headers()
                output = template.render(logined=True, user=user, login_errors={})
                handler.wfile.write(output.encode("utf-8"))
                return
            else:
                login_errors = {"auth_err": "wrong password or username"}
        else:
            login_errors = {"auth_err": "wrong password or username"}

        output = template.render(logined=False, user = {}, login_errors=login_errors)

        cookie_data["login_errors"] = json.dumps(login_errors)
        cookie_data["login_errors"]["path"] = "/login"

        handler.send_response(400)
        handler.send_header("Content-Type", "text/html")
        handler.send_header("Set-Cookie", cookie_data["login_errors"].output(header=""))
        handler.end_headers()

        handler.wfile.write(output.encode("utf-8"))


def get_cookie_data(cookie):
    user = {}; errors = {}; secret_key = {}; data = {}
    login_data = {}; login_errors = {}
    if "user" in cookie:
        user = json.loads(cookie["user"].value)
    if "errors" in cookie:
        errors = json.loads(cookie["errors"].value)
    if "data" in cookie:
        data = json.loads(cookie["data"].value)
    if "login_data" in cookie:
        login_data = json.loads(cookie["login_data"].value)
    if "login_errors" in cookie:
        login_errors = json.loads(cookie["login_errors"].value)

    return {"user": user,
            "errors": errors,
            "secret_key": secret_key,
            "data": data,
            "login_data": login_data,
            "login_errors": login_errors}
