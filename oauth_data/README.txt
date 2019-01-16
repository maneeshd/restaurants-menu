1. Firstly, create developer accounts in Google and Facebook and register the app to get the client/app id. (Follow online guides to get this done.)
2. Download the Google OAuth2 Client Credentials JSON and rename it to gOAuth.json
3. Create a new JSON file for Facebook Login called fbOAuth.json and put the following details inside it:
{
  "web": {
    "api_version": "<version of the facebook api you are using(v3.2)>",
    "app_id": "<app id for your app>",
    "app_secret": "<app secret for your app>"
  }
}
Put the above two files in 'oauth_data' dir.
