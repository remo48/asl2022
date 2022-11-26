from logging.config import dictConfig
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

LOG_CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        }
    },
    "handlers": {
        "wsgi": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": "web-server.log",
            "maxBytes": 1024,
        }
    },
    "root": {"level": "INFO", "handlers": ["wsgi"]},
}
dictConfig(LOG_CONFIG)

SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:secret@localhost:3306/imovies"
# CA_SERVER_IP = "10.0.99.50"
CA_SERVER_IP = "127.0.0.1"
CA_SERVER_PORT = 5000
CA_CERT="/home/web-server/web-server/certs/ca.crt"
SERVER_CERT="/home/web-server/web-server/certs/server.crt"
SERVER_KEY="/home/web-server/web-server/certs/server.key"