from flask import Flask
from db_queries import db
from views import login_manager, web

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile("config.py")
    setup_extensions(app)
    app.register_blueprint(web, url_prefix='')
    return app

def setup_extensions(app):
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    db.init_app(app)

app = create_app()