import os
import pathlib
from dotenv import load_dotenv

import re

import requests
from flask import Flask, session, abort, redirect, request
from flask_cors import CORS

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask import render_template

load_dotenv()
app = Flask(__name__)
CORS(app)

app.config['DEBUG'] = os.environ.get("FLASK_DEBUG")
app.secret_key = os.environ.get("app_secret_key")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
client_secret = os.environ.get("client_secret")

API_NAME = "tasks"
API_VERSION = "V1"

OAUTHLIB_INSECURE_TRANSPORT = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")

#client_secrets_file = os.path.join(pathlib.Path(__file__).parent, client_secret)
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
SCOPES = ["https://www.googleapis.com/auth/userinfo.email","https://www.googleapis.com/auth/userinfo.profile", "openid", "https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/tasks"]
redirect_uri = "https://test-6kumec5grq-ue.a.run.app/callback"

flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file, scopes=SCOPES,
    redirect_uri="https://test-6kumec5grq-ue.a.run.app/callback")

def login_is_required(function):
    def wrapper(*args, **kwargs):
      if "google_id" not in session:
        return abort(401) #Authorization Required
      else:
        return function(*args, **kwargs)
    return wrapper

# Commission Calculator
def calculate_commission(system_size, ppw, adders, dealer_fees_percentage, redline):

    total_sale_price = system_size * ppw
    total_cost = (system_size * (dealer_fees_percentage+redline)) + adders
    commission = total_sale_price - total_cost

    return commission


@app.route("/login")
def login():
  authorization_url, state = flow.authorization_url()
  session["state"] = state
  return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    # Inside your callback function, after the credentials have been obtained
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return render_template('app.html')

@app.route("/logout")
def logout():
  session.clear()
  return redirect("/")

@app.route("/")
def index():
  if 'counter' not in session:
    session['counter'] = 0
  return render_template('index.html', counter=session['counter'])

@app.route('/toggle', methods=['POST'])
def toggle():
    session['counter'] += 1
    return {'counter': session['counter']}

@app.route('/calculate', methods=['POST', 'GET'])
def calculate():
  if request.method == 'POST':
    if request.form['action'] == 'calculate':
      ppw = float(request.form['ppw'])
      dealer_fees_percentage = float(request.form['dealer_fees_percentage'])
      adders = float(request.form['adders'])
      redline = float(request.form['redline'])
      system_size = float(request.form['system_size'])
  
      commission = calculate_commission(system_size, ppw, adders, dealer_fees_percentage, redline)
  
      result = {
      "commission": commission,
      "ppw": ppw,
      "dealer_fees_percentage": dealer_fees_percentage,
      "adders": adders,
      "redline": redline,
      "system_size": system_size
      }

      return render_template('calculate.html', result = result)

    elif request.form['action'] == 'send_to_sheets':
    

      ppw = request.form['ppw']
      dealer_fees_percentage = request.form['dealer_fees_percentage']
      adders = request.form['adders']
      redline = request.form['redline']
      system_size = request.form['system_size']

      customer_name = request.form['customer_name']
      customer_address = request.form['customer_address']
      google_sheets_url = request.form['google_sheets_url']
      sheet_name = request.form['sheet_name']

      values = [customer_name, customer_address, google_sheets_url, sheet_name, ppw, dealer_fees_percentage, redline, adders, system_size]

      for value in values:
        if value:  # Check if the string is not empty
          continue
        else:
          return render_template('incomplete.html')     

      ppw = float(request.form['ppw'])
      dealer_fees_percentage = float(request.form['dealer_fees_percentage'])
      adders = float(request.form['adders'])
      redline = float(request.form['redline'])
      system_size = float(request.form['system_size'])

      commission = calculate_commission(system_size, ppw, adders, dealer_fees_percentage, redline)

      # Regular expression to match the Google Sheets ID pattern
      pattern = r"/spreadsheets/d/([a-zA-Z0-9-_]+)"

      # Search for matches in the URL
      match = re.search(pattern, google_sheets_url)

      # Extract the spreadsheet ID if a match was found
      spreadsheet_id = match.group(1) if match else None

      stored_data = []

    # Iterate over the session object and store key-value pairs in a list
      for key, value in session.items():
        stored_data.append({"key": key, "value": value})

      access_token = stored_data[1]["value"]["token"]

      spreadsheet_url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/{sheet_name}:append?valueInputOption=USER_ENTERED"
      
      headers = {
          'Authorization': f'Bearer {access_token}',
          'Content-Type': 'application/json'
      }

      data = {
          "values": [
              [
                  "Commission Calculator", customer_name, customer_address, ppw, dealer_fees_percentage, redline, adders, system_size, commission
              ]
          ]
      }

      response = requests.post(spreadsheet_url, headers=headers, json=data)

      return render_template('sent_to_sheets.html')

    else:
        # Handle unexpected action value
      return render_template('incomplete.html')




@app.route('/lead_tracker', methods=['POST', 'GET'])
def lead_tracker():
  if request.method == 'POST':

      door_to_door = request.form['door_to_door']
      conversions_door_to_door = request.form['conversions_door_to_door']

      referrals = request.form['referrals']
      conversions_referrals = request.form['conversions_referrals']

      online_inquiries = request.form['online_inquiries']
      conversions_online_inquiries = request.form['conversions_online_inquiries']

      google_sheets_url = request.form['google_sheets_url']
      sheet_name = request.form['sheet_name']

      date_today = request.form['date_today']

      values = [door_to_door, conversions_door_to_door, referrals, conversions_referrals, online_inquiries, conversions_online_inquiries, google_sheets_url, sheet_name, date_today]

      for value in values:
        if value:  # Check if the string is not empty
          continue
        else:
          return render_template('incomplete.html')   

      # Regular expression to match the Google Sheets ID pattern
      pattern = r"/spreadsheets/d/([a-zA-Z0-9-_]+)"

      # Search for matches in the URL
      match = re.search(pattern, google_sheets_url)

      # Extract the spreadsheet ID if a match was found
      spreadsheet_id = match.group(1) if match else None

      stored_data = []

    # Iterate over the session object and store key-value pairs in a list
      for key, value in session.items():
        stored_data.append({"key": key, "value": value})

      access_token = stored_data[1]["value"]["token"]

      spreadsheet_url = f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/{sheet_name}:append?valueInputOption=USER_ENTERED"
      
      headers = {
          'Authorization': f'Bearer {access_token}',
          'Content-Type': 'application/json'
      }

      data = {
          "values": [
              [
                  "Leads Tracker", door_to_door, conversions_door_to_door, referrals, conversions_referrals, online_inquiries, conversions_online_inquiries, date_today
              ]
          ]
      }
      response = requests.post(spreadsheet_url, headers=headers, json=data)
      return render_template('sent_to_sheets.html')




@app.route("/protected_area")
@login_is_required
def protected_area():
  stored_data = []

# Iterate over the session object and store key-value pairs in a list
  for key, value in session.items():
    stored_data.append({"key": key, "value": value})


  access_token = stored_data[1]["value"]["token"]


  # Google Sheets URL
  url = 'https://docs.google.com/spreadsheets/d/1SbjSzhu7uk3dFFjQrjz-8kJFctPZLyS-P800kdNWRGE/edit#gid=0'

  # Regular expression to match the Google Sheets ID pattern
  pattern = r"/spreadsheets/d/([a-zA-Z0-9-_]+)"

  # Search for matches in the URL
  match = re.search(pattern, url)

  # Extract the spreadsheet ID if a match was found
  spreadsheet_id = match.group(1) if match else None

  spreadsheet_id


  url = 'https://sheets.googleapis.com/v4/spreadsheets/1SbjSzhu7uk3dFFjQrjz-8kJFctPZLyS-P800kdNWRGE/values/Sheet1:append?valueInputOption=USER_ENTERED'
  data = {
    "values": [
        ["value1", "value2", "value3"],
        ["value4", "value5", "value6"],
        ["value7", "value8", "value9"]
    ]
  }
  headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
  }

  # Make the GET request with the headers
  response = requests.post(url, headers=headers, json=data)

  if response.status_code == 200:
    # Print the response JSON if successful

    return f"Hello {session['name']}! Response: {response} <br/> <a href='/logout'><button>Logout</button></a>"
  
  else:
    # Print the error if the request failed
    return(f'Error: {response.status_code}')
    return(response.text)

  #return f"Hello {session['name']}! All keys and values: {stored_data} here are your tasks:  <br/> <a href='/logout'><button>Logout</button></a>"
  

if __name__ == "__main__":
    app.run()