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

SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI")
CORE_CA_URL = os.getenv("CORE_CA_URL")
CA_CERT= os.getenv("ROOT_CERT")
SERVER_CERT= os.getenv("SERVER_CERT")
SERVER_KEY= os.getenv("SERVER_KEY")