#!/usr/bin/env python3
"""
Author: Maneesh Divana <maneeshd77@gmail.com>
Date: 01-01-2019
Python Interperter: 3.6.8

Server code for Restaurants Menu WebApp with OAuth2
"""
from __future__ import print_function
from os import urandom, environ
from flask import Flask, redirect, render_template, flash, jsonify
from flask import request, Response, Markup, session as user_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker as db_session_maker
from sqlalchemy.orm.exc import NoResultFound
from db_models import BASE, Restaurant, MenuItem, User
from bleach import clean as clean_markup
from json import load as load_json_file
from json import loads as load_json_string
from json import dumps as dump_json_string
from google.oauth2 import id_token as gauth_id_token
from google.auth.transport.requests import Request as GAuthRequest
from httplib2 import Http
from base64 import urlsafe_b64encode as encode_uid, urlsafe_b64decode as decode_uid


# Flask App Setup
APP = Flask(__name__)
APP.config["SECRET_KEY"] = str(urandom(32))

# DB Setup
if environ.get("DATABASE_URL"):
    DB_ENGINE = create_engine(environ.get("DATABASE_URL"))
else:
    DB_ENGINE = create_engine("sqlite:///restaurant_menu_with_users.db")
BASE.metadata.bind = DB_ENGINE
DB_SESSION = db_session_maker(bind=DB_ENGINE)

# Google OAuth2 Data
try:
    with open("./oauth_data/gOAuth.json") as fd:
        GOAUTH_DATA = load_json_file(fd)
    GOAUTH_CLIENT_ID = GOAUTH_DATA["web"]["client_id"]
    GOAUTH_URI = GOAUTH_DATA["web"]["auth_uri"]
    GOAUTH_TOKEN_URI = GOAUTH_DATA["web"]["token_uri"]
    GOAUTH_CLIENT_SECRET = GOAUTH_DATA["web"]["client_secret"]
except Exception as goauth_err:
    print("\n[GoogleOAuthError]", goauth_err)
    print("Please make sure Google OAuth2 Client ID JSON file: gOAuth.json "
          "is present in the same directory level as server.py.")
    print("You can download the Google OAuth2 Client ID JSON file from your projects' "
          "'Creentials' section in Google API Console.\n")
    exit(1)


# Facebook OAuth2 Data
try:
    with open("./oauth_data/fbOAuth.json") as fd:
        FB_OAUTH_DATA = load_json_file(fd)
    FB_OAUTH_API_VERSION = FB_OAUTH_DATA["web"]["api_version"]
    FB_OAUTH_APP_ID = FB_OAUTH_DATA["web"]["app_id"]
    FB_OAUTH_APP_SECRET = FB_OAUTH_DATA["web"]["app_secret"]
except Exception as fboauth_err:
    print("\n[FacebookOAuthError]", fboauth_err)
    print("Please make sure Facebook OAuth2 App ID JSON file: fbOAuth.json "
          "is present in the same directory level as server.py.")
    exit(1)


# DB Helper Methods
def create_user(name, email, picture=""):
    db_session = None
    picture = picture if picture else None
    try:
        db_session = DB_SESSION()
        user = User(name=name, email=email, picture=picture)
        db_session.add(user)
        db_session.commit()
        print("New user created:", str(user))
        user = db_session.query(User).filter_by(email=email).first()
        if user:
            return user.id
    except Exception as exp:
        print("[CreateUserError]", exp)
    finally:
        if db_session:
            db_session.close()


def get_user_info(user_id):
    db_session = None
    try:
        db_session = DB_SESSION()
        user = db_session.query(User).filter_by(id=user_id).one()
        if user:
            return user.serialize
    except Exception as exp:
        print("[GetUserInfoError]", exp)
    finally:
        if db_session:
            db_session.close()


def get_user_id(email):
    db_session = None
    try:
        db_session = DB_SESSION()
        user = db_session.query(User).filter_by(email=email).one()
        if user:
            return user.id
    except Exception as exp:
        print("[GetUserIdError]", exp)
    finally:
        if db_session:
            db_session.close()


def update_user(user_id, name, picture):
    db_session = None
    try:
        db_session = DB_SESSION()
        user = db_session.query(User).filter_by(id=user_id).one()
        if user:
            user.name = name
            user.picture = picture
            db_session.add(user)
            db_session.commit()
    except Exception as exp:
        print("[UpdateUserIdError]", exp)
    finally:
        if db_session:
            db_session.close()


@APP.route("/gconnect", methods=["POST"])
def g_connect():
    try:
        request_data = request.get_json(force=True)
        csrf_token = request_data.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session["secret"]:
            print("\n! CSRF_TOKEN ERROR !")
            print("SERVER_CSRF_TOKEN:", user_session["uid"])
            print("CLIENT_CSRF_TOKEN:", csrf_token, "\n")
            clear_session_data()
            return Response(
                response=dump_json_string("Cross Site Request Forgery Detected"),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        id_token = request_data.get("id_token")
        access_token = request_data.get("access_token")

        if not id_token or not access_token:
            clear_session_data()
            return Response(
                response=dump_json_string("Invlaid Request. Please provide id_token and access_token."),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        gauth_data = gauth_id_token.verify_oauth2_token(
            id_token,
            GAuthRequest(),
            GOAUTH_CLIENT_ID
        )

        iss = gauth_data["iss"]
        aud = gauth_data["aud"]
        azp = gauth_data["azp"]

        if iss != "accounts.google.com" or (azp != aud != GOAUTH_CLIENT_ID):
            raise ValueError

        gauth_id = gauth_data["sub"]
        name = gauth_data["name"]
        email = gauth_data["email"]
        picture = gauth_data["picture"]

        url = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={0}".format(access_token)
        http = Http()
        resp = load_json_string(http.request(url)[1])

        # If there was an error in the access token info, abort.
        if resp.get("error"):
            print("[AccessTokenError] {0}".format(resp.get("error")))
            clear_session_data()
            return Response(
                response=dump_json_string(resp.get("error")),
                status=500,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify that the access token is used for the intended user
        if resp.get("sub", "NA") != gauth_id:
            print("[AccessTokenError] User IDs don't match."
                  " id_token['sub']={0} & access_token['sub']={1}".format(gauth_id, resp.get("sub", "NA")))
            clear_session_data()
            return Response(
                response=dump_json_string("Tokens' user id doesn't match with apps' user id."),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify that the access token is valid for this app.
        if resp.get("azp", "NA") != GOAUTH_CLIENT_ID or resp.get("aud", "NA") != GOAUTH_CLIENT_ID:
            print("[AccessTokenError] azp, aud and client id don't match.")
            print("aud:", resp.get("aud", "NA"))
            print("azp:", resp.get("azp", "NA"))
            print("client_id:", GOAUTH_CLIENT_ID)
            clear_session_data()
            return Response(
                response=dump_json_string("Tokens' client id doesn't match with apps' client id."),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )
        user_session["auth_provider"] = "google"
        stored_access_token = user_session.get("access_token")
        stored_gauth_id = user_session.get("gauth_id")
        if stored_access_token and stored_gauth_id == gauth_id:
            return Response(
                response=dump_json_string("OK"),
                status=200,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Create or Get Local User connected to the Google User
        user_id = get_user_id(email)
        if not user_id:
            user_id = create_user(name, email, picture)
        else:
            update_user(user_id, name, picture)
        user_session["user_id"] = user_id

        user_session["access_token"] = access_token
        user_session["gauth_id"] = gauth_id
        user_session["user"] = dict(
            name=name,
            email=email,
            picture=picture,
        )
        user_session["logged_in"] = True

        flash("Successfully logged in as {0} using Google.".format(name), "success")
        return jsonify(status="OK")
    except ValueError as exp:
        print("Invlaid ID Token")
        print(exp)
        clear_session_data()
        return Response(
            response=dump_json_string("Invlaid Authentication Token"),
            status=401,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )
    except Exception as unexp:
        print("[GConnect] Unexpected Error!")
        print(unexp)
        clear_session_data()
        return Response(
            response=dump_json_string("Unexpected Server Error"),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )


@APP.route("/fbconnect", methods=["POST"])
def fb_connect():
    try:
        request_data = request.get_json(force=True)
        csrf_token = request_data.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session["secret"]:
            print("\n! CSRF_TOKEN ERROR !")
            print("SERVER_CSRF_TOKEN:", user_session["uid"])
            print("CLIENT_CSRF_TOKEN:", csrf_token, "\n")
            clear_session_data()
            return Response(
                response=dump_json_string("Cross Site Request Forgery Detected"),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )
        access_token = request_data.get("access_token")
        profile_url = "https://graph.facebook.com/{0}/me?" \
                      "access_token={1}&" \
                      "fields=name,email,id,picture".format(FB_OAUTH_API_VERSION, access_token)
        http = Http()
        response = http.request(profile_url)
        if response[0]["status"] == "200":
            profile_data = load_json_string(response[1])
            name = profile_data.get("name")
            email = profile_data.get("email")
            fb_auth_id = profile_data.get("id")
            picture = profile_data.get("picture", {}).get("data", {}).get("url", "")
            if not name or not email or not fb_auth_id:
                clear_session_data()
                return Response(
                    response=dump_json_string("Failed to get authentication response from Facebook"),
                    status=401,
                    mimetype="application/json",
                    content_type="application/json; charset=utf-8"
                )

            user_session["auth_provider"] = "facebook"
            stored_access_token = user_session.get("access_token")
            stored_fb_auth_id = user_session.get("fb_auth_id")
            if stored_access_token and stored_fb_auth_id == fb_auth_id:
                return Response(
                    response=dump_json_string("OK"),
                    status=200,
                    mimetype="application/json",
                    content_type="application/json; charset=utf-8"
                )

            # Create or Get Local User connected to the Google User
            user_id = get_user_id(email)
            if not user_id:
                user_id = create_user(name, email, picture)
            else:
                update_user(user_id, name, picture)
            user_session["user_id"] = user_id

            user_session["access_token"] = access_token
            user_session["fb_auth_id"] = fb_auth_id
            user_session["user"] = dict(
                name=name,
                email=email,
                picture=picture,
            )
            user_session["logged_in"] = True

            flash("Successfully logged in as {0} using Facebook.".format(name), "success")
            return jsonify(status="OK")
        else:
            clear_session_data()
            return Response(
                response=dump_json_string("Invlaid Authentication Token"),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )
    except Exception as unexp:
        print("[FbConnect] Unexpected Error!")
        print(unexp)
        clear_session_data()
        return Response(
            response=dump_json_string("Unexpected Server Error"),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )


def clear_session_data():
    user_session["logged_in"] = False
    if user_session.get("uid"):
        del user_session["uid"]
    if user_session.get("secret"):
        del user_session["secret"]
    if user_session.get("access_token"):
        del user_session["access_token"]
    if user_session.get("user"):
        del user_session["user"]
    if user_session.get("user_id"):
        del user_session["user_id"]
    if user_session.get("gauth_id"):
        del user_session["gauth_id"]
    if user_session.get("auth_provider"):
        del user_session["auth_provider"]
    if user_session.get("fb_auth_id"):
        del user_session["fb_auth_id"]


def g_disconnect(token):
    try:
        http = Http()
        resp = http.request(
            uri="https://accounts.google.com/o/oauth2/revoke?token={0}".format(token),
            method="POST",
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        if resp[0]["status"] == "200":
            print("[GDisconnect] Successfully revoked Google OAuth2 access_token.")
            return True
        else:
            print("[GDisconnect] Failed to revoke access_token.\n", resp)
            return False
    except Exception as exp:
        print("[GDisconnectError]", exp)


def fb_disconnect(user_id, access_token):
    try:
        url = "https://graph.facebook.com/{0}/permissions?access_token={1}".format(user_id, access_token)
        http = Http()
        resp = http.request(url, "DELETE")
        if resp[0]["status"] == "200":
            print("[FbDisconnect] Successfully Revoked Facebook access_token.")
            return True
        else:
            print("[FbDisconnect] Failed to revoke Facebook access_token.\n", resp)
            return False
    except Exception as exp:
        print("[FbDisconnectError]", exp)


@APP.route("/login/")
@APP.route("/login")
def login():
    user_session["secret"] = urandom(32)
    session_id = encode_uid(user_session["secret"]).decode()
    user_session["uid"] = session_id
    return render_template(
        "login.html",
        gauth_client_id=GOAUTH_CLIENT_ID,
        csrf_token=user_session["uid"],
        fb_api_ver=FB_OAUTH_API_VERSION,
        fb_app_id=FB_OAUTH_APP_ID
    )


@APP.route("/logout/", methods=["POST"])
@APP.route("/logout", methods=["POST"])
def logout():
    try:
        if user_session.get("uid"):
            request_data = request.get_json(force=True)
            if request_data:
                csrf_token = request_data.get("csrf_token", "NA").encode()
                if decode_uid(csrf_token) == user_session["secret"]:
                    if user_session["auth_provider"] == "google":
                        g_disconnect(user_session.get("access_token"))
                    else:
                        fb_disconnect(user_session["fb_auth_id"], user_session["access_token"])
                    return jsonify(status="OK")
                else:
                    print(decode_uid(csrf_token))
                    print(user_session["secret"])
                    return jsonify(status="CSRF Token Mismatch!")
            else:
                return jsonify(status="Invalid Request Data!")
        else:
            return jsonify(status="OK")
    except Exception as exp:
        print("[LogoutError]", exp)
        return jsonify(status="Unexpected Error")
    finally:
        clear_session_data()


@APP.route("/restaurants/")
@APP.route("/restaurants")
@APP.route("/")
def home():
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    restaurants = list()
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(Restaurant).all()
        restaurants = [row.serialize for row in result]
    except NoResultFound:
        print("[WARNING] No restaurants found in database!")
        flash("No restaurants found.", "danger")
    except Exception as exp:
        print("[ERROR]", exp)
        flash("An unexpected error has occurred in the server", "danger")
    finally:
        if db_session:
            db_session.close()
        return render_template(
            "restaurants.html",
            restaurants=restaurants,
            user=user_session.get("user", None),
            gauth_client_id=GOAUTH_CLIENT_ID,
            csrf_token=user_session.get("uid", ""),
            fb_api_ver=FB_OAUTH_API_VERSION,
            fb_app_id=FB_OAUTH_APP_ID
        )


@APP.route("/restaurants/add/", methods=["GET", "POST"])
@APP.route("/restaurants/add", methods=["GET", "POST"])
def add_restaurant():
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        name = request.form.get("restaurant_name")
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        if name:
            name = str(clean_markup(name)).strip()
            restaurant = Restaurant(name=name, user_id=user_session["user_id"])
            try:
                db_session = DB_SESSION()
                db_session.add(restaurant)
                db_session.commit()
                print("[INFO] Added new restaurant: {0}".format(restaurant))
                message = Markup("New restaurant added: <b>{0}</b>".format(name))
                print(message)
                flash(message, "success")
            except Exception as exp:
                print("[ERROR]", exp)
                flash("An unexpected error has occurred in the server", "danger")
            finally:
                if db_session:
                    db_session.close()
        else:
            flash("Invalid restaurant name. Did not add new restaurant.", "danger")
        return redirect("/")
    else:
        return render_template(
            "add_restaurant.html",
            user=user_session.get("user", None),
            gauth_client_id=GOAUTH_CLIENT_ID,
            csrf_token=user_session.get("uid", ""),
            fb_api_ver=FB_OAUTH_API_VERSION,
            fb_app_id=FB_OAUTH_APP_ID
        )


@APP.route("/restaurants/<int:rid>/edit/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/edit", methods=["GET", "POST"])
def edit_restaurant(rid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        name = request.form.get("restaurant_name")
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        if name:
            name = str(clean_markup(name)).strip()
            try:
                db_session = DB_SESSION()
                restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
                if restaurant:
                    if restaurant.user_id != user_session["user_id"]:
                        flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                        return redirect("/restaurants/{0}/menu".format(rid))
                    old_name = restaurant.name
                    if old_name == name:
                        pass
                    else:
                        old_restaurant = str(restaurant)
                        restaurant.name = name
                        db_session.add(restaurant)
                        db_session.commit()
                        print("[INFO] Changed restaurant from {0} to {1}".format(old_restaurant, restaurant))
                        message = Markup(
                            "Restaurants' name changed from <b>{0}</b> to <b>{1}</b>".format(old_name, name)
                        )
                        flash(message, "primary")
                else:
                    raise NoResultFound
            except NoResultFound:
                print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
                flash("Unable find the restaurant in database", "warning")
            except Exception as exp:
                print("[ERROR]", exp)
                flash("An unexpected error has occurred in the server", "danger")
            finally:
                if db_session:
                    db_session.close()
        else:
            flash("Invalid restaurant name. Did not change restaurants' name.")
        return redirect("/restaurants/{0}/menu".format(rid))
    else:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant).filter_by(rid=rid).first()
            if result:
                restaurant = result.serialize
                if restaurant["user_id"] != user_session["user_id"]:
                    flash("Unauthorized Access. You are not the owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                return render_template(
                    "edit_restaurant.html",
                    restaurant=restaurant,
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    fb_api_ver=FB_OAUTH_API_VERSION,
                    fb_app_id=FB_OAUTH_APP_ID
                )
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/delete/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/delete", methods=["GET", "POST"])
def delete_restaurant(rid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        try:
            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if restaurant:
                if restaurant.user_id != user_session["user_id"]:
                    flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                db_session.delete(restaurant)
                db_session.commit()
                print("[INFO] Deleted restaurant: {0}".format(restaurant))
                message = Markup("Restaurant deleted: <b>{0}</b>".format(restaurant.name))
                flash(message, "warning")
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
        finally:
            if db_session:
                db_session.close()
            return redirect("/")
    else:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant).filter_by(rid=rid).one()
            if result:
                restaurant = result.serialize
                if restaurant["user_id"] != user_session["user_id"]:
                    flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                return render_template(
                    "delete_restaurant.html",
                    restaurant=restaurant,
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    fb_api_ver=FB_OAUTH_API_VERSION,
                    fb_app_id=FB_OAUTH_APP_ID
                )
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/menu/")
@APP.route("/restaurants/<int:rid>/menu")
def restaurant_menu(rid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(Restaurant).filter_by(rid=rid).first()
        if result:
            restaurant = result.serialize
            owner = get_user_info(restaurant["user_id"])

            if owner["id"] != user_session["user_id"]:
                restricted_view = True
            else:
                restricted_view = False

            result = db_session.query(MenuItem).filter_by(rid=rid).all()
            if result:
                menu_items = [row.serialize for row in result]
                courses = ["appetizer", "entree", "dessert", "beverage"]
                appetizers = [item for item in menu_items if item["course"].lower() == courses[0]]
                entrees = [item for item in menu_items if item["course"].lower() == courses[1]]
                desserts = [item for item in menu_items if item["course"].lower() == courses[2]]
                beverages = [item for item in menu_items if item["course"].lower() == courses[3]]
                others = [item for item in menu_items if item["course"].lower() not in courses]

                return render_template(
                    "menu_items.html",
                    restaurant=restaurant,
                    appetizers=appetizers,
                    entrees=entrees,
                    desserts=desserts,
                    beverages=beverages,
                    others=others,
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    restricted_view=restricted_view,
                    owner=owner,
                    fb_api_ver=FB_OAUTH_API_VERSION,
                    fb_app_id=FB_OAUTH_APP_ID
                )
            else:
                message = Markup("Menu is empty for restaurant <b>{0}</b>".format(restaurant["name"]))
                flash(message, "warning")

                return render_template(
                    "menu_items.html",
                    restaurant=restaurant,
                    appetizers=[],
                    entrees=[],
                    desserts=[],
                    beverages=[],
                    others=[],
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    restricted_view=restricted_view,
                    owner=owner,
                    fb_api_ver=FB_OAUTH_API_VERSION,
                    fb_app_id=FB_OAUTH_APP_ID
                )
        else:
            raise NoResultFound
    except NoResultFound:
        print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
        flash("Unable find the restaurant in database", "danger")
        return redirect("/")
    except Exception as exp:
        print("[ERROR]", exp)
        flash("An unexpected error has occurred in the server", "danger")
        return redirect("/")
    finally:
        if db_session:
            db_session.close()


@APP.route("/restaurants/<int:rid>/menu/add/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/menu/add", methods=["GET", "POST"])
def add_menu_item(rid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        try:
            name = request.form.get("name")
            desc = request.form.get("desc", "")
            course = request.form.get("course")
            price = request.form.get("price")
            csrf_token = request.form.get("csrf_token", "NA").encode()
            if decode_uid(csrf_token) != user_session.get("secret", "?????"):
                flash("Invalid CSRF Token", "danger")
                return redirect("/login")

            # Validation
            courses = ["Appetizer", "Entree", "Desert", "Beverage"]
            invalid = False
            if not name or not course or not price or len(price) > 4 or course not in courses:
                invalid = True
            try:
                int(price.replace("$", ""))
            except Exception as exp:
                del exp
                try:
                    float(price.replace("$", ""))
                except Exception as exp:
                    del exp
                    invalid = True

            if invalid:
                return Response(
                    response="Invalid Request",
                    status=400,
                    mimetype="text/html",
                    content_type="text/html; charset=utf-8"
                )

            # Clean the input to prevent malicious scripting attack
            name = clean_markup(name).strip()
            desc = clean_markup(desc).strip()
            course = clean_markup(course).strip()
            price = clean_markup(price).strip()

            if not str(price).startswith("$"):
                price = "$" + price

            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if restaurant and restaurant.user_id != user_session["user_id"]:
                flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            menu_item = MenuItem(name=name,
                                 course=course,
                                 description=desc,
                                 price=price,
                                 rid=rid,
                                 user_id=restaurant.user_id)
            db_session.add(menu_item)
            db_session.commit()
            flash("Menu item: {0} added".format(name), "success")
            return redirect("/restaurants/{0}/menu".format(rid))
        except Exception as exp:
            print("[ERROR]", exp)
            flash("Error while adding menu item", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()
    else:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant).filter_by(rid=rid).one()
            if result:
                restaurant = result.serialize
                if restaurant["user_id"] != user_session["user_id"]:
                    flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                return render_template(
                    "add_menu_item.html",
                    restaurant=restaurant,
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    fb_api_ver=FB_OAUTH_API_VERSION,
                    fb_app_id=FB_OAUTH_APP_ID
                )
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/menu/<int:mid>/edit/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/menu/<int:mid>/edit", methods=["GET", "POST"])
def edit_menu_item(rid, mid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        try:
            name = request.form.get("name")
            desc = request.form.get("desc", "")
            course = request.form.get("course")
            price = request.form.get("price")
            csrf_token = request.form.get("csrf_token", "NA").encode()
            if decode_uid(csrf_token) != user_session.get("secret", "?????"):
                flash("Invalid CSRF Token", "danger")
                return redirect("/login")

            # Validation
            courses = ["Appetizer", "Entree", "Desert", "Beverage"]
            invalid = False
            if not name or not course or not price or len(price) > 4 or course not in courses:
                print("1")
                invalid = True
            try:
                int(price.replace("$", ""))
            except Exception as exp:
                print("2")
                del exp
                try:
                    float(price.replace("$", ""))
                except Exception as exp:
                    del exp
                    print("3")
                    invalid = True

            if invalid:
                return Response(
                    response="Invalid Request",
                    status=400,
                    mimetype="text/html",
                    content_type="text/html; charset=utf-8"
                )

            # Clean the input to prevent malicious scripting attack
            name = clean_markup(name).strip()
            desc = clean_markup(desc).strip()
            course = clean_markup(course).strip()
            price = clean_markup(price).strip()

            if not str(price).startswith("$"):
                price = "$" + price

            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if restaurant and restaurant.user_id != user_session["user_id"]:
                flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            menu_item = db_session.query(MenuItem).filter_by(rid=rid).filter_by(mid=mid).first()
            if menu_item:
                menu_item.name = name
                menu_item.description = desc
                menu_item.course = course
                menu_item.price = price
                db_session.add(menu_item)
                db_session.commit()
                flash("Menu item edited successfully", "primary")
                return redirect("/restaurants/{0}/menu".format(rid))
            else:
                flash("Menu item not found", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
        except Exception as exp:
            print("[ERROR]", exp)
            flash("Error while editing menu item", "danger")
            return redirect("/restaurants/{0}/menu".format(rid))
        finally:
            if db_session:
                db_session.close()
    else:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant).filter_by(rid=rid).first()
            if result:
                restaurant = result.serialize
                if restaurant["user_id"] != user_session["user_id"]:
                    flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                result = db_session.query(MenuItem).filter_by(rid=rid).filter_by(mid=mid).first()
                if result:
                    item = result.serialize
                    return render_template(
                        "edit_menu_item.html",
                        restaurant=restaurant,
                        item=item,
                        user=user_session.get("user", None),
                        gauth_client_id=GOAUTH_CLIENT_ID,
                        csrf_token=user_session.get("uid", ""),
                        fb_api_ver=FB_OAUTH_API_VERSION,
                        fb_app_id=FB_OAUTH_APP_ID
                    )
                else:
                    flash("Menu item not found", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/menu/<int:mid>/delete/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/menu/<int:mid>/delete", methods=["GET", "POST"])
def delete_menu_item(rid, mid):
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        try:
            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if restaurant and restaurant.user_id != user_session["user_id"]:
                flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            menu_item = db_session.query(MenuItem).filter_by(rid=rid).filter_by(mid=mid).first()
            if menu_item:
                db_session.delete(menu_item)
                db_session.commit()
                flash("Menu item deleted successfully", "info")
                return redirect("/restaurants/{0}/menu".format(rid))
            else:
                flash("Menu item not found", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
        except Exception as exp:
            print("[ERROR]", exp)
            flash("Error while editing menu item", "danger")
            return redirect("/restaurants/{0}/menu".format(rid))
        finally:
            if db_session:
                db_session.close()
    else:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant).filter_by(rid=rid).first()
            if result:
                restaurant = result.serialize
                if restaurant["user_id"] != user_session["user_id"]:
                    flash("Unauthorized Access. You are not thr owner of the restaurant!", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                result = db_session.query(MenuItem).filter_by(rid=rid).filter_by(mid=mid).first()
                if result:
                    item = result.serialize
                    return render_template(
                        "delete_menu_item.html",
                        restaurant=restaurant,
                        item=item,
                        user=user_session.get("user", None),
                        gauth_client_id=GOAUTH_CLIENT_ID,
                        csrf_token=user_session.get("uid", ""),
                        fb_api_ver=FB_OAUTH_API_VERSION,
                        fb_app_id=FB_OAUTH_APP_ID
                    )
                else:
                    flash("Menu item not found", "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
            else:
                raise NoResultFound
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


if __name__ == '__main__':
    if environ.get("PORT"):
        PORT = environ.get("PORT")
    else:
        PORT = 5000
    APP.run(
        host="localhost",
        port=PORT,
        debug=True,
        threaded=True
    )
