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
from handlers import *

env = Environment(loader=FileSystemLoader("./templates/"))
# Replace these with your MySQL database credentials
MYSQL_CONFIG = {
    "user": os.environ["user"],
    "password": os.environ["password"],
    "host": os.environ["host"],
    "port": os.environ["port"],
    "database": os.environ["database"],
}


class HttpProcessor(BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers", "X-Requested-With, Content-type"
        )

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def login_page_post(self, cursor, cnx):
        pass

    def do_POST(self):
        cnx = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = cnx.cursor()
        match self.path:
            case "/":
                FormCRUD.form_page_post(self, cursor, cnx, env)
            case "/login" | "/login/":
                FormCRUD.login_page_post(self, cursor, cnx, env)

        cursor.close()
        cnx.close()


    def do_GET(self):
        match self.path:
            case "/":
                FormCRUD.form_page_get(self, env)
            case "/login" | "/login/":
                FormCRUD.login_page_get(self, env)



# Set up the server
serv = HTTPServer(("0.0.0.0", 3307), HttpProcessor)
serv.serve_forever()
