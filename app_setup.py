"""
Application database setup
"""
from os import getenv
from db_models import create_models
from db_util import populate_db

DB_URI = getenv("DATABASE_URL") if getenv(
    "DATABASE_URL") else "sqlite:///restaurant_menu_with_users.db"

# Create the DB models
create_models(DB_URI)

# If env var is set populate the db
if getenv("POPULATE_DB"):
    populate_db(DB_URI)
