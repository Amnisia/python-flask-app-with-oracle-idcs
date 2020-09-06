from flask import Flask, render_template, redirect, request, session
import requests
import IdcsClient
import json

app = Flask(__name__)

# A secret key is needed for a session
app.secret_key = 'secret'


# Definition of the /auth route
@app.route('/auth', methods=['POST', 'GET'])
def auth():

    # Load the configurations
    options = getoptions()

    # Authentication Manager loads configurations
    am = IdcsClient.AuthenticationManager(options)

    '''
    Use the Authentication Manager to generate the Authorization Code URL, pass the
    application's callback URL as a parameter along with the code value and code parameter
    '''
    url = am.getAuthorizationCodeUrl(options["redirectURL"], options["scope"], "1234", "code")

    # Redirect the browser to the Oracle Identity Cloud Service Authorization URL.
    return redirect(url, code=302)

# Function to load the configurations from the config.json file
def getoptions():
    fo = open("config.json", "r")
    config = fo.read()
    options = json.loads(config)
    return options


# Definition of the /logout route
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    id_token = (session.get("id_token", None))

    options = getoptions()

    url = options["BaseUrl"]
    url += options["logoutSufix"]
    url += '?post_logout_redirect_uri=http%3A//localhost%3A8000&id_token_hint='
    url += id_token

    # Clears the Flask client-side session (also done on a manual page refresh)
    session.clear()

    # Redirect to the Oracle Identity Cloud Service logout URL
    return redirect(url, code=302)


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/home', methods=['POST', 'GET'])
def home():

    # Call the IDCS API to get id_token
    # if not authenticated, a 400 status code will be returned and user will not be able to proceed
    # if authenticated, a 200 status code is returned and it allows the app to render the protected html

    options = getoptions()

    # 'code' is the authorization code which is needed to get id_token
    # uses the flask.request library (different from the Python requests library) to auth
    session['code'] = request.args.get('code')

    data = {
        'grant_type': 'authorization_code',
        'code': session['code'],
        'redirect_uri': options['redirectURL']
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }

    response = requests.post(options['BaseUrl'] + '/oauth2/v1/token?', data=data, headers=headers,
                             auth=(options['ClientId'], options['ClientSecret']))

    session['id_token'] = response.json().get("id_token")

    if str(response.status_code) != "200":
        return render_template('login.html')

    return render_template('home.html')


if __name__ == '__main__':
    app.run(port=8000, debug=True)
    