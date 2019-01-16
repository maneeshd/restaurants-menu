from os import environ
from db_models import create_models
from db_util import populate_db


DB_URI = environ.get("DATABASE_URL") if environ.get("DATABASE_URL") else "sqlite:///restaurant_menu_with_users.db"

# Create the DB models
create_models(DB_URI)

# If env var is set populate the db
if environ.get("POPULATE_DB"):
    populate_db(DB_URI)
