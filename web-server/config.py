from logging.config import dictConfig
import os

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

