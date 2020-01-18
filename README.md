# Restaurants' Menu
A CRUD WebApp using Flask, SQLAlchemy with Google and Facebook OAuth2 listing various restaurants and their menus and menu items.

Users can view the menu items but only owners of the restaurants can edit/delete menu items and edit/delete restaurants.

Any user can add a new restaurant and add menu items to it.

**Live version is hosted [here](https://maneeshd-restaurants.herokuapp.com/).**

## Design

- App uses [Flask](http://flask.pocoo.org/) web framework in python in the backend

- App uses [SQLAlchemy](https://www.sqlalchemy.org/) as Object Relational Mapper(ORM) to run SQL from Python.

- Data is stored in an [SQLite](https://www.sqlite.org/index.html) database.

- App uses [Bootstrap](https://getbootstrap.com/) and [jQuery](https://jquery.com/) in the frontend.

- App uses [Jinja2](http://jinja.pocoo.org/docs/) template engine to do server-side rendering.

## Requirements

- Python >= 3.5.2
- See [requirements.txt](requirements.txt) for python package requirements.
- A developer account at [Google](https://console.developers.google.com/apis/credentials) for Google OAuth2 Login Credentials.
- A developer account at [Facebook](https://developers.facebook.com/) for Facebook OAuth2 Login Credentials.

## Running the application

Assuming that [Python](https://www.python.org/downloads/) >= 3.5.2 (preferably 3.6.8) is installed (a [virtualenv](https://virtualenv.pypa.io/en/latest/) is recommended) - 

* Install the python packages required to run the application using:
```bash
(py3)$ pip install -r requirements.txt -U
```

* Create the database tables using
```bash
(py3)$ python db_models.py
```

* Populate the databse with initial set of data using:
```bash
(py3)$ python db_util.py
```

* Register and create client credentials with Google and Facebook (guides to create the same are available in their respective homepages and also on many other sites.)

* Put the Google and Facebook client credential secrets in `gAuth.json` and `fbAuth.json` files respectively inside [oauth_data](oauth_data).

* Run the server using:
```bash
(py3)$ python server.py
```

* Application can be accessed at http://localhost:5000 or http://localhost:5000/restaurants


### REST API JSON Endpoints

* `/api/v1/restaurants` - **`GET`** - Will get the name and rid of all the restaurants registered in the app.

* `/api/v1/restaurants/1` - **`GET`** - Will get the details of restaurant with rid=1.

* `/api/v1/restaurants/1/menu` - **`GET`** - Will get the menu for the restaurant with rid=1.

* `/api/v1/restaurants/1/menu/1` - **`GET`** - Will get the menu item details with mid=1 from restaurant with rid=1.

* `/api/v1/get_owner_for_restaurant?rid=1` - **`GET`** - Will get the owner of the restaurant with rid=1.

* `/api/v1/get_restaurants_for_user?user_id=1` - **`GET`** - Will get all the restaurants owned by user with user_id=1.

Run the REST API calls using the API URIs' from above `http://localhost:5000/api/v1....` .
