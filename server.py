#!/usr/bin/env python3
"""
Author: Maneesh Divana <maneeshd77@gmail.com>
Date: 11-01-2019
Python Interperter: 3.6.8

Server code for Restaurants Menu WebApp with OAuth2
"""
from __future__ import print_function
from os import urandom, getenv
from json import load as load_json_file
from json import dumps as dump_json_string
from base64 import urlsafe_b64encode as encode_uid
from base64 import urlsafe_b64decode as decode_uid
from flask import Flask, redirect, render_template, flash, jsonify
from flask import request, Response, Markup, session as user_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker as db_session_maker
from sqlalchemy.orm.exc import NoResultFound
from bleach import clean as clean_markup
from google.oauth2 import id_token as gauth_id_token
from google.auth.transport.requests import Request as GAuthRequest
from db_models import BASE, Restaurant, MenuItem, User
from requests import get, post, delete


# Flask App Setup
APP = Flask(__name__)
APP.config["SECRET_KEY"] = str(urandom(32))

# DB Setup
if getenv("DATABASE_URL"):
    DB_ENGINE = create_engine(getenv("DATABASE_URL"))
else:
    DB_ENGINE = create_engine("sqlite:///restaurant_menu_with_users.db")
BASE.metadata.bind = DB_ENGINE
DB_SESSION = db_session_maker(bind=DB_ENGINE)

# Google OAuth2 Data
try:
    with open("./oauth_data/gAuth.json") as fd:
        GOAUTH_DATA = load_json_file(fd)
    GOAUTH_CLIENT_ID = GOAUTH_DATA["web"]["client_id"]
    GOAUTH_URI = GOAUTH_DATA["web"]["auth_uri"]
    GOAUTH_TOKEN_URI = GOAUTH_DATA["web"]["token_uri"]
    GOAUTH_CLIENT_SECRET = GOAUTH_DATA["web"]["client_secret"]
except Exception as goauth_err:
    print("\n[GoogleOAuthError]", goauth_err)
    print("Please make sure Google OAuth2 Client ID JSON file: gAuth.json "
          "is present in the same directory level as server.py.")
    print(
        "You can download the Google OAuth2 Client ID JSON file from your "
        "projects' "
        "'Creentials' section in Google API Console.\n")
    exit(1)

# Facebook OAuth2 Data
try:
    with open("./oauth_data/fbAuth.json") as fd:
        FB_OAUTH_DATA = load_json_file(fd)
    FB_OAUTH_API_VER = FB_OAUTH_DATA["web"]["api_version"]
    FB_OAUTH_APP_ID = FB_OAUTH_DATA["web"]["app_id"]
    FB_OAUTH_APP_SECRET = FB_OAUTH_DATA["web"]["app_secret"]
except Exception as fboauth_err:
    print("\n[FacebookOAuthError]", fboauth_err)
    print("Please make sure Facebook OAuth2 App ID JSON file: fbAuth.json "
          "is present in the same directory level as server.py.")
    exit(1)


# DB Helper Methods
def create_user(name, email, picture=""):
    """
    Create a User in database.

    :param name: Full name of the user
    :param email: E-mail id of the user
    :param picture: Link to the profile picture
    :return: Created Users' ID in database
    """
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
        return None
    except Exception as exp:
        print("[CreateUserError]", exp)
        return None
    finally:
        if db_session:
            db_session.close()


def get_user_info(user_id):
    """
    Get name, email and profile picture link for a given user id.

    :param user_id: User ID in database.
    :return: A dictionary containing the above user info.
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        user = db_session.query(User).filter_by(id=user_id).one()
        if user:
            return user.serialize
        return dict()
    except Exception as exp:
        print("[GetUserInfoError]", exp)
        return dict()
    finally:
        if db_session:
            db_session.close()


def get_user_id(email):
    """
    Given the email id of the user get the user id in database.

    :param email: Email id of the user.
    :return: Users' ID in database
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        user = db_session.query(User).filter_by(email=email).one()
        if user:
            return user.id
        return None
    except Exception as exp:
        print("[GetUserIdError]", exp)
        return None
    finally:
        if db_session:
            db_session.close()


def update_user(user_id, name, picture):
    """
    Updates the user info (full name & profile picture link) in database.
    *Note: Email id cannot be changed.

    :param user_id: Users' ID in database
    :param name: Full name of the user
    :param picture: Profile picture link
    :return: None
    """
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
    """
    Flask Route to handle Google OAuth2 Sign-in.
    Verifies the 'id_token' sent by frontend and gets the user info from
    Google and authorizes Users of the app.
    Accepts only POST requests.

    :return: A Response Object
    """
    try:
        # Get the POSTed JSON data
        request_data = request.get_json(force=True)

        # Verify CSRF Token
        csrf_token = request_data.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session["secret"]:
            print("\n! CSRF_TOKEN ERROR !")
            print("SERVER_CSRF_TOKEN:", user_session["uid"])
            print("CLIENT_CSRF_TOKEN:", csrf_token, "\n")
            clear_session_data()
            return Response(
                response=dump_json_string(
                    "Cross Site Request Forgery Detected"),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Get id_token and access_token
        id_token = request_data.get("id_token")
        access_token = request_data.get("access_token")

        if not id_token or not access_token:
            # If id_token or access_token is not present clear curent session
            clear_session_data()
            return Response(
                response=dump_json_string(
                    "Invlaid Request. Please provide id_token and "
                    "access_token."),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify the id_token with Google
        gauth_data = gauth_id_token.verify_oauth2_token(
            id_token,
            GAuthRequest(),
            GOAUTH_CLIENT_ID
        )

        iss = gauth_data["iss"]
        aud = gauth_data["aud"]
        azp = gauth_data["azp"]

        # Check if the Google Auth response has the corect Client ID of the app
        if iss != "accounts.google.com" or (azp != aud != GOAUTH_CLIENT_ID):
            raise ValueError

        gauth_id = gauth_data["sub"]
        name = gauth_data["name"]
        email = gauth_data["email"]
        picture = gauth_data["picture"]

        # Verify the access_token
        url = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" \
              "{0}".format(access_token)
        get_req = get(url)
        resp = get_req.json()

        # If there was an error in the access token info, abort.
        if get_req.status_code != 200:
            print(
                "[AccessTokenError] {0}".format(resp.get("error_description"))
            )
            clear_session_data()
            return Response(
                response=dump_json_string(resp.get("error_description")),
                status=500,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify that the access token is used for the intended user
        if resp.get("sub", "NA") != gauth_id:
            print("[AccessTokenError] User IDs don't match. id_token['sub']={0}"
                  " & access_token['sub']={1}".format(gauth_id,
                                                      resp.get("sub", "NA")))
            clear_session_data()
            return Response(
                response=dump_json_string(
                    "Tokens' user id doesn't match with apps' user id."
                ),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify that the access token is valid for this app.
        if (resp.get("azp", "NA") != GOAUTH_CLIENT_ID or
                resp.get("aud", "NA") != GOAUTH_CLIENT_ID):
            print("[AccessTokenError] azp, aud and client id don't match.")
            print("aud:", resp.get("aud", "NA"))
            print("azp:", resp.get("azp", "NA"))
            print("client_id:", GOAUTH_CLIENT_ID)
            clear_session_data()
            return Response(
                response=dump_json_string(
                    "Tokens' client id doesn't match with apps' client id."),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Everything good so far. Check if user is already logged in.
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

        # Create or Get Local User connected to the Google User.
        user_id = get_user_id(email)
        if not user_id:
            user_id = create_user(name, email, picture)
        else:
            update_user(user_id, name, picture)
        user_session["user_id"] = user_id

        # Store the Google User ID, access_token, user info in session
        user_session["access_token"] = access_token
        user_session["gauth_id"] = gauth_id
        user_session["user"] = dict(
            name=name,
            email=email,
            picture=picture,
        )

        # Google OAuth2 Sign-in Successful
        user_session["logged_in"] = True
        flash("Successfully logged in as {0} using Google.".format(name),
              "success")
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
    """
    Flask Route to handle Facebook OAuth2 Sign-in.
    Verifies the 'access_token' sent by frontend and gets the user info from
    Facebook and authorizes Users of the app.
    Accepts only POST requests.

    :return: A Response Object
    """
    try:
        # Get the POSTed JSON data
        request_data = request.get_json(force=True)

        # Verify CSRF Token
        csrf_token = request_data.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session["secret"]:
            print("\n! CSRF_TOKEN ERROR !")
            print("SERVER_CSRF_TOKEN:", user_session["uid"])
            print("CLIENT_CSRF_TOKEN:", csrf_token, "\n")
            clear_session_data()
            return Response(
                response=dump_json_string(
                    "Cross Site Request Forgery Detected"),
                status=401,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )

        # Verify the access_token with Facebook and get user info
        access_token = request_data.get("access_token")
        profile_url = "https://graph.facebook.com/{0}/me?access_token={1}&" \
                      "fields=name,email,id,picture".format(FB_OAUTH_API_VER,
                                                            access_token)
        get_req = get(profile_url)

        if get_req.status_code == 200:
            # Request success
            profile_data = get_req.json()
            name = profile_data.get("name")
            email = profile_data.get("email")
            fb_auth_id = profile_data.get("id")
            picture = profile_data.get("picture", {}).get("data", {}).get("url",
                                                                          "")
            if not name or not email or not fb_auth_id:
                # If user info not in facebook response, send error response.
                clear_session_data()
                return Response(
                    response=dump_json_string(
                        "Failed to get authentication response from Facebook"),
                    status=401,
                    mimetype="application/json",
                    content_type="application/json; charset=utf-8"
                )

            # Everything's good so far. Verify if user is already logged in.
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

            # Create or Get Local User connected to the Facebook User
            user_id = get_user_id(email)
            if not user_id:
                user_id = create_user(name, email, picture)
            else:
                update_user(user_id, name, picture)

            # Store the user info, access_token etc in session.
            user_session["user_id"] = user_id
            user_session["access_token"] = access_token
            user_session["fb_auth_id"] = fb_auth_id
            user_session["user"] = dict(
                name=name,
                email=email,
                picture=picture,
            )

            # Facebook OAuth2 Sign-in Successful
            user_session["logged_in"] = True
            flash("Successfully logged in as {0} using Facebook.".format(name),
                  "success")
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
    """
    Clear the current user session variables.

    :return: None
    """
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
    """
    Revoke permissions granted to the app from Google and
    invalidate the access_token.

    :param token: access_token from Google
    :return: True if successful else False
    """
    uri = "https://accounts.google.com/o/oauth2/revoke?token={0}".format(token)
    try:
        resp = post(url=uri,
                    headers={
                        'content-type': 'application/x-www-form-urlencoded'
                    })
        if resp.status_code == 200:
            print(
                "[GDisconnect] Successfully revoked Google OAuth2 "
                "access_token.")
            return True
        print("[GDisconnect] Failed to revoke access_token.\n", resp)
        return False
    except Exception as exp:
        print("[GDisconnectError]", exp)


def fb_disconnect(user_id, access_token):
    """
    Revoke permissions granted to the app from Facebook and
    invalidate the access_token.

    :param user_id: Facebook user id
    :param access_token: Facebook access_token
    :return: True if successful else False
    """
    try:
        url = "https://graph.facebook.com/{0}/permissions?" \
              "access_token={1}".format(user_id, access_token)
        resp = delete(url)
        if resp.status_code == 200:
            print("[FbDisconnect] Successfully Revoked Facebook access_token.")
            return True
        print("[FbDisconnect] Failed to revoke Facebook access_token.\n", resp)
        return False
    except Exception as exp:
        print("[FbDisconnectError]", exp)


@APP.route("/login/")
@APP.route("/login")
def login():
    """
    Flask route to handle user logins.

    :return: Rendered Jinja2 HTML Template
    """
    # Create a secure CSRF Token for the user session.
    user_session["secret"] = urandom(32)
    session_id = encode_uid(user_session["secret"]).decode()
    user_session["uid"] = session_id
    return render_template(
        "login.html",
        gauth_client_id=GOAUTH_CLIENT_ID,
        csrf_token=user_session["uid"],
        fb_api_ver=FB_OAUTH_API_VER,
        fb_app_id=FB_OAUTH_APP_ID
    )


@APP.route("/logout/", methods=["POST"])
@APP.route("/logout", methods=["POST"])
def logout():
    """
    Flask route to handle user logouts based on the auth provider.

    :return: JSON response
    """
    try:
        if user_session.get("uid"):
            request_data = request.get_json(force=True)
            if request_data:
                # Verify CSRF Token
                csrf_token = request_data.get("csrf_token", "NA").encode()
                if decode_uid(csrf_token) == user_session["secret"]:
                    if user_session["auth_provider"] == "google":
                        g_disconnect(user_session.get("access_token"))
                    else:
                        fb_disconnect(user_session["fb_auth_id"],
                                      user_session["access_token"])
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
    """
    Flask route to display the home page/all restaurants list page.

    :return: Rendered Jinja2 HTML Template
    """
    # Validate that user is logged in
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
            fb_api_ver=FB_OAUTH_API_VER,
            fb_app_id=FB_OAUTH_APP_ID
        )


@APP.route("/restaurants/add/", methods=["GET", "POST"])
@APP.route("/restaurants/add", methods=["GET", "POST"])
def add_restaurant():
    """
    Flask route to handle adding of a new restaurant.

    :return: Rendered Jinja2 HTML Template
    """
    # Validate that the user is logged in
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")

    db_session = None
    if request.method == "POST":
        name = request.form.get("restaurant_name")
        # Verify CSRF Token
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
                message = Markup(
                    "New restaurant added: <b>{0}</b>".format(name))
                print(message)
                flash(message, "success")
            except Exception as exp:
                print("[ERROR]", exp)
                flash("An unexpected error has occurred in the server",
                      "danger")
            finally:
                if db_session:
                    db_session.close()
        else:
            flash("Invalid restaurant name. Did not add new restaurant.",
                  "danger")
        return redirect("/")
    else:
        return render_template(
            "add_restaurant.html",
            user=user_session.get("user", None),
            gauth_client_id=GOAUTH_CLIENT_ID,
            csrf_token=user_session.get("uid", ""),
            fb_api_ver=FB_OAUTH_API_VER,
            fb_app_id=FB_OAUTH_APP_ID
        )


@APP.route("/restaurants/<int:rid>/edit/", methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/edit", methods=["GET", "POST"])
def edit_restaurant(rid):
    """
    Flask route to handle editing a restaurants name.

    :param rid: Restaurants ID
    :return: Rendered Jinja2 HTML Template
    """
    # Validate that the user is logged in
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")

    # If POST request update info in db and redirect, else render edit page.
    db_session = None
    if request.method == "POST":
        name = request.form.get("restaurant_name")
        # Validate the CSRF Token
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        if name:
            name = str(clean_markup(name)).strip()
            try:
                db_session = DB_SESSION()
                restaurant = db_session.query(Restaurant)\
                                       .filter_by(rid=rid)\
                                       .one()
                if not restaurant:
                    raise NoResultFound
                # Verify that user is the owner to edit
                if restaurant.user_id != user_session["user_id"]:
                    flash(
                        "Unauthorized Access. You are not thr owner of "
                        "the restaurant!",
                        "danger")
                    return redirect("/restaurants/{0}/menu".format(rid))
                old_name = restaurant.name
                if old_name == name:
                    pass
                else:
                    old_restaurant = str(restaurant)
                    restaurant.name = name
                    db_session.add(restaurant)
                    db_session.commit()
                    print("[INFO] Changed restaurant from {0} to {1}".format(
                        old_restaurant, restaurant))
                    message = Markup(
                        "Restaurants' name changed from <b>{0}</b> to "
                        "<b>{1}</b>".format(old_name, name)
                    )
                    flash(message, "primary")
            except NoResultFound:
                print(
                    "[WARNING] Restaurant(rid={0}) not found in "
                    "database!".format(
                        rid))
                flash("Unable find the restaurant in database", "warning")
            except Exception as exp:
                print("[ERROR]", exp)
                flash("An unexpected error has occurred in the server",
                      "danger")
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
            if not result:
                raise NoResultFound
            restaurant = result.serialize
            if restaurant["user_id"] != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not the owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            return render_template(
                "edit_restaurant.html",
                restaurant=restaurant,
                user=user_session.get("user", None),
                gauth_client_id=GOAUTH_CLIENT_ID,
                csrf_token=user_session.get("uid", ""),
                fb_api_ver=FB_OAUTH_API_VER,
                fb_app_id=FB_OAUTH_APP_ID
            )
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(
                rid))
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
    """
    Flask route to handle the deletion of a restaurant.

    :param rid: Restaurants ID
    :return: Rendered Jinja2 HTML Template
    """
    # Validate that the user is logged in
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")

    # If POST request delete and redirect, if GET request render delete page.
    db_session = None
    if request.method == "POST":
        # Verify CSRF Token
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        try:
            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if not restaurant:
                raise NoResultFound
            # Verify user is the owner to delete
            if restaurant.user_id != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            db_session.delete(restaurant)
            db_session.commit()
            print("[INFO] Deleted restaurant: {0}".format(restaurant))
            message = Markup(
                "Restaurant deleted: <b>{0}</b>".format(restaurant.name))
            flash(message, "warning")
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(
                rid))
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
            if not result:
                raise NoResultFound
            restaurant = result.serialize
            # Verify that user is the owner to delete
            if restaurant["user_id"] != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            return render_template(
                "delete_restaurant.html",
                restaurant=restaurant,
                user=user_session.get("user", None),
                gauth_client_id=GOAUTH_CLIENT_ID,
                csrf_token=user_session.get("uid", ""),
                fb_api_ver=FB_OAUTH_API_VER,
                fb_app_id=FB_OAUTH_APP_ID
            )
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(
                rid))
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
    """
    Flask route to handle the viewing of menu of a restaurant.

    :param rid: Restaurants ID
    :return: Rendered Jinja2 HTML Template
    """
    # Verify that the user is logged in
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(Restaurant).filter_by(rid=rid).first()
        if not result:
            raise NoResultFound
        restaurant = result.serialize
        owner = get_user_info(restaurant["user_id"])

        restricted_view = True if owner["id"] != user_session["user_id"] \
            else False

        result = db_session.query(MenuItem).filter_by(rid=rid).all()
        if result:
            menu_items = [row.serialize for row in result]
            courses = ["appetizer", "entree", "dessert", "beverage"]
            appetizers = [item for item in menu_items if
                          item["course"].lower() == courses[0]]
            entrees = [item for item in menu_items if
                       item["course"].lower() == courses[1]]
            desserts = [item for item in menu_items if
                        item["course"].lower() == courses[2]]
            beverages = [item for item in menu_items if
                         item["course"].lower() == courses[3]]
            others = [item for item in menu_items if
                      item["course"].lower() not in courses]

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
                fb_api_ver=FB_OAUTH_API_VER,
                fb_app_id=FB_OAUTH_APP_ID
            )
        # No menu items added for the restaurant
        message = Markup(
            "Menu is empty for restaurant <b>{0}</b>".format(
                restaurant["name"]))
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
            fb_api_ver=FB_OAUTH_API_VER,
            fb_app_id=FB_OAUTH_APP_ID
        )
    except NoResultFound:
        print(
            "[WARNING] Restaurant(rid={0}) not found in database!".format(rid))
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
    """
    Flask route to handle the adding of menu item to a restaurant.

    :param rid: Restaurants ID
    :return: Rendered Jinja2 HTML Template
    """
    # Validate that the user is logged in
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

            # Verify CSRF Token
            csrf_token = request.form.get("csrf_token", "NA").encode()
            if decode_uid(csrf_token) != user_session.get("secret", "?????"):
                flash("Invalid CSRF Token", "danger")
                return redirect("/login")

            # Validation
            courses = ["Appetizer", "Entree", "Desert", "Beverage"]
            invalid = False
            if (not name or not course or not price or
                    len(price) > 4 or course not in courses):
                print("[EditMenuItem] Invalid user input.")
                invalid = True
            try:
                int(price.replace("$", ""))
            except Exception as exp:
                del exp
                try:
                    float(price.replace("$", ""))
                except Exception as exp:
                    del exp
                    print("[EditMenuItem] Item Price is neither in int format "
                          "nor in float format")
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
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
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
            if not result:
                raise NoResultFound
            restaurant = result.serialize
            if restaurant["user_id"] != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            return render_template(
                "add_menu_item.html",
                restaurant=restaurant,
                user=user_session.get("user", None),
                gauth_client_id=GOAUTH_CLIENT_ID,
                csrf_token=user_session.get("uid", ""),
                fb_api_ver=FB_OAUTH_API_VER,
                fb_app_id=FB_OAUTH_APP_ID
            )
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(
                rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/menu/<int:mid>/edit/",
           methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/menu/<int:mid>/edit",
           methods=["GET", "POST"])
def edit_menu_item(rid, mid):
    """
    Flask route to handle the editing of menu item.

    :param rid: Restaurants ID
    :param mid: Menut Item ID
    :return: Rendered Jinja2 HTML Template
    """
    # Verify that the user is logged in
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

            # Validate CSRF Token
            csrf_token = request.form.get("csrf_token", "NA").encode()
            if decode_uid(csrf_token) != user_session.get("secret", "?????"):
                flash("Invalid CSRF Token", "danger")
                return redirect("/login")

            # Input data validation
            courses = ["Appetizer", "Entree", "Desert", "Beverage"]
            invalid = False
            if (not name or not course or not price or
                    len(price) > 4 or course not in courses):
                print("[EditMenuItem] Invalid user input.")
                invalid = True
            try:
                int(price.replace("$", ""))
            except Exception as exp:
                del exp
                try:
                    float(price.replace("$", ""))
                except Exception as exp:
                    del exp
                    print("[EditMenuItem] Price is neither in int nor "
                          "in float format.")
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
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            menu_item = db_session.query(MenuItem).filter_by(rid=rid).filter_by(
                mid=mid).first()
            if menu_item:
                menu_item.name = name
                menu_item.description = desc
                menu_item.course = course
                menu_item.price = price
                db_session.add(menu_item)
                db_session.commit()
                flash("Menu item edited successfully", "primary")
                return redirect("/restaurants/{0}/menu".format(rid))
            # Menu Item not found
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
            if not result:
                raise NoResultFound
            restaurant = result.serialize
            if restaurant["user_id"] != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            result = db_session.query(MenuItem).filter_by(
                rid=rid).filter_by(mid=mid).first()
            if result:
                item = result.serialize
                return render_template(
                    "edit_menu_item.html",
                    restaurant=restaurant,
                    item=item,
                    user=user_session.get("user", None),
                    gauth_client_id=GOAUTH_CLIENT_ID,
                    csrf_token=user_session.get("uid", ""),
                    fb_api_ver=FB_OAUTH_API_VER,
                    fb_app_id=FB_OAUTH_APP_ID
                )
            # Menu Item not found
            flash("Menu item not found", "danger")
            return redirect("/restaurants/{0}/menu".format(rid))
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found in database!".format(
                rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/restaurants/<int:rid>/menu/<int:mid>/delete/",
           methods=["GET", "POST"])
@APP.route("/restaurants/<int:rid>/menu/<int:mid>/delete",
           methods=["GET", "POST"])
def delete_menu_item(rid, mid):
    """
    Flask route to handle the deletion of menu item.

    :param rid: Restaurants ID
    :param mid: Menut Item ID
    :return: Rendered Jinja2 HTML Template
    """
    # Verify that user is logged in
    if not user_session.get("logged_in") or not user_session.get("uid"):
        flash("Please login", "info")
        return redirect("/login")
    db_session = None
    if request.method == "POST":
        # Validate CSRF Token
        csrf_token = request.form.get("csrf_token", "NA").encode()
        if decode_uid(csrf_token) != user_session.get("secret", "?????"):
            flash("Invalid CSRF Token", "danger")
            return redirect("/login")
        try:
            db_session = DB_SESSION()
            restaurant = db_session.query(Restaurant).filter_by(rid=rid).one()
            if restaurant and restaurant.user_id != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            menu_item = db_session.query(MenuItem)\
                                  .filter_by(rid=rid)\
                                  .filter_by(mid=mid)\
                                  .first()
            if menu_item:
                db_session.delete(menu_item)
                db_session.commit()
                flash("Menu item deleted successfully", "info")
                return redirect("/restaurants/{0}/menu".format(rid))
            # Menu item not found
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
            if not result:
                raise NoResultFound
            restaurant = result.serialize
            if restaurant["user_id"] != user_session["user_id"]:
                flash(
                    "Unauthorized Access. You are not thr owner of the "
                    "restaurant!",
                    "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            result = db_session.query(MenuItem).filter_by(
                rid=rid).filter_by(mid=mid).first()
            if not result:
                flash("Menu item not found", "danger")
                return redirect("/restaurants/{0}/menu".format(rid))
            item = result.serialize
            return render_template(
                "delete_menu_item.html",
                restaurant=restaurant,
                item=item,
                user=user_session.get("user", None),
                gauth_client_id=GOAUTH_CLIENT_ID,
                csrf_token=user_session.get("uid", ""),
                fb_api_ver=FB_OAUTH_API_VER,
                fb_app_id=FB_OAUTH_APP_ID
            )
        except NoResultFound:
            print("[WARNING] Restaurant(rid={0}) not found "
                  "in database!".format(rid))
            flash("Unable find the restaurant in database", "danger")
            return redirect("/")
        except Exception as exp:
            print("[ERROR]", exp)
            flash("An unexpected error has occurred in the server", "danger")
            return redirect("/")
        finally:
            if db_session:
                db_session.close()


@APP.route("/api/v1/restaurants/")
@APP.route("/api/v1/restaurants")
def api_get_all_restaurants():
    """
    REST API URI to get all restaurants

    :return: JSON
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(Restaurant).all()
        if not result:
            raise NoResultFound
        restaurants = [row.serialize for row in result]
        return jsonify(restaurants)
    except NoResultFound:
        return jsonify(dict(
            ERROR="No restuarants were found!"
        ))
    except Exception as exp:
        print("[ApiError][GetAllRestaurants]", exp)
        return Response(
            response=dump_json_string({
                "ERROR": "Oops! Server is not feeling good."
            }),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )
    finally:
        if db_session:
            db_session.close()


@APP.route("/api/v1/restaurant/<int:rid>/")
@APP.route("/api/v1/restaurant/<int:rid>")
def api_restaurant_detail(rid):
    """
    REST API URI to get one restaurants' detail

    :param rid: Restaurant ID
    :return: JSON
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(Restaurant). \
            filter_by(rid=rid). \
            join(Restaurant.user). \
            with_entities(Restaurant.rid, Restaurant.name, User.name). \
            one()
        if not result:
            raise NoResultFound
        return jsonify(dict(
            rid=result[0],
            name=result[1],
            owner=result[2]
        ))
    except NoResultFound:
        return jsonify(dict(
            ERROR="Restaurant Not Found"
        ))
    except Exception as exp:
        print("[ApiError][GetRestaurantDetail]", exp)
        return Response(
            response=dump_json_string({
                "ERROR": "Oops! Server is not feeling good."
            }),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )
    finally:
        if db_session:
            db_session.close()


@APP.route("/api/v1/restaurants/<int:rid>/menu/")
@APP.route("/api/v1/restaurants/<int:rid>/menu")
def api_menu_items(rid):
    """
    REST API URI to get the menu of a restaurant

    :param rid: Restaurant ID
    :return: JSON
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(MenuItem). \
            filter_by(rid=rid). \
            all()
        if not result:
            raise NoResultFound
        menu_items = [row.serialize for row in result]
        return jsonify(menu_items)
    except NoResultFound:
        return jsonify(list())
    except Exception as exp:
        print("[ApiError][GetMenuItems]", exp)
        return Response(
            response=dump_json_string({
                "ERROR": "Oops! Server is not feeling good."
            }),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )
    finally:
        if db_session:
            db_session.close()


@APP.route("/api/v1/restaurants/<int:rid>/menu/<int:mid>/")
@APP.route("/api/v1/restaurants/<int:rid>/menu/<int:mid>")
def api_menu_item_detail(rid, mid):
    """
    REST API URI to get the details of a menu item

    :param rid: Restaurant ID
    :param mid: Menu Item ID
    :return: JSON
    """
    db_session = None
    try:
        db_session = DB_SESSION()
        result = db_session.query(MenuItem). \
            filter_by(rid=rid, mid=mid). \
            one()
        if not result:
            raise NoResultFound
        return jsonify(result.serialize)
    except NoResultFound:
        return jsonify(list())
    except Exception as exp:
        print("[ApiError][GetMenuItemDetail]", exp)
        return Response(
            response=dump_json_string({
                "ERROR": "Oops! Server is not feeling good."
            }),
            status=500,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )
    finally:
        if db_session:
            db_session.close()


@APP.route("/api/v1/get_owner_for_restaurant")
def is_user_the_owner():
    """
    REST API URI to get the owner for a restaurant

    :return: JSON
    """
    db_session = None
    rid = request.args.get("rid")
    if rid:
        try:
            db_session = DB_SESSION()
            result = db_session.query(User). \
                join(User.restaurant). \
                filter_by(rid=rid). \
                one()
            if not result:
                raise NoResultFound
            return jsonify(result.serialize)
        except NoResultFound:
            return jsonify(dict())
        except Exception as exp:
            print("[APIError][GetRestaurantOwner]", exp)
            return Response(
                response=dump_json_string({
                    "ERROR": "Oops! Server is not feeling good."
                }),
                status=500,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )
        finally:
            if db_session:
                db_session.close()
    else:
        return Response(
            response=dump_json_string({
                "ERROR": "rid must be passed as url parameter(?rid=1)"
            }),
            status=400,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )


@APP.route("/api/v1/get_restaurants_for_user")
def get_restauratnts_for_user():
    """
    REST API URI to get all the restaurants owned by a user.

    :return: JSON
    """
    db_session = None
    user_id = request.args.get("user_id")
    if user_id:
        try:
            db_session = DB_SESSION()
            result = db_session.query(Restaurant). \
                filter_by(user_id=user_id). \
                all()
            if not result:
                raise NoResultFound
            restaurants = [row.serialize for row in result]
            return jsonify(restaurants)
        except NoResultFound:
            return jsonify(list())
        except Exception as exp:
            print("[APIError][GetRestaurantOwner]", exp)
            return Response(
                response=dump_json_string({
                    "ERROR": "Oops! Server is not feeling good."
                }),
                status=500,
                mimetype="application/json",
                content_type="application/json; charset=utf-8"
            )
        finally:
            if db_session:
                db_session.close()
    else:
        return Response(
            response=dump_json_string({
                "ERROR": "user_id must be passed as url parameter(?user_id=1)"
            }),
            status=400,
            mimetype="application/json",
            content_type="application/json; charset=utf-8"
        )


if __name__ == '__main__':
    if getenv("PORT"):
        PORT = getenv("PORT")
    else:
        PORT = 5000
    APP.run(
        host="localhost",
        port=PORT,
        debug=True,
        threaded=True
    )
