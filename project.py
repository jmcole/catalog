# Flora Catalog Application. Developed by John Cole in Udacity Full-Stack Nanodegree Program

from flask import (Flask, render_template, request, redirect,
    jsonify, url_for, flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Park, FloraList, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Park Flora Application"

app.secret_key = 'hot dog'
engine = create_engine('postgresql://parkfloradatabase')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login')
def showLogin():
    # Create anti-forgery state token

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response
        (json.dumps('Current user is already connected.'),
         200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:150px;\
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    # Revoke a current user's token and reset their login_session
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/park/<int:park_id>/floralist/JSON')
def parkFloraJSON(park_id):
    # Returns all flora by park ID
    park = session.query(Park).filter_by(id=park_id).one()
    items = session.query(FloraList).filter_by(
        park_id=park_id).all()
    return jsonify(FloraLists=[i.serialize for i in items])


@app.route('/park/<int:park_id>/floralist/<int:floralist_id>/JSON')
def floralistItemJSON(park_id, floralist_id):
    # Returns individual flora item by Park
    Flora_List = session.query(FloraList).filter_by(id=floralist_id).one()
    return jsonify(Flora_List=Flora_List.serialize)


@app.route('/park/JSON')
def parksJSON():
    # Returns all parks
    parks = session.query(Park).all()
    return jsonify(parks=[r.serialize for r in parks])


@app.route('/')
@app.route('/park/')
def showParks():
    # Show all parks
    parks = session.query(Park).order_by(asc(Park.name))
    if 'username' not in login_session:
        return render_template('publicparks.html', parks=parks)
    else:
        return render_template('parks.html', parks=parks)


@app.route('/park/new/', methods=['GET', 'POST'])
@login_required
def newPark():
    # Create a new park
    if request.method == 'POST':
        newPark = Park(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newPark)
        flash('New Park %s Successfully Created' % newPark.name)
        session.commit()
        return redirect(url_for('showParks'))
    else:
        return render_template('newPark.html')


@app.route('/park/<int:park_id>/edit/', methods=['GET', 'POST'])
@login_required
def editPark(park_id):
    # Edit Park
    editedPark = session.query(
        Park).filter_by(id=park_id).one()
    if editedPark.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
                to edit this park. Please create your own park in order to \
                edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedPark.name = request.form['name']
            flash('Park Successfully Edited %s' % editedPark.name)
            return redirect(url_for('showParks'))
    else:
        return render_template('editPark.html', park=editedPark)


@app.route('/park/<int:park_id>/delete/', methods=['GET', 'POST'])
@login_required
def deletePark(park_id):
    # Delete a park
    parkToDelete = session.query(
        Park).filter_by(id=park_id).one()
    if parkToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to\
            delete this park. Please create your own park in order to \
            delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(parkToDelete)
        flash('%s Successfully Deleted' % parkToDelete.name)
        session.commit()
        return redirect(url_for('showParks', park_id=park_id))
    else:
        return render_template('deletePark.html', park=parkToDelete)


@app.route('/park/<int:park_id>/')
@app.route('/park/<int:park_id>/floralist/')
def showFlora(park_id):
    # Show a park floralist
    park = session.query(Park).filter_by(id=park_id).one()
    creator = getUserInfo(park.user_id)
    items = session.query(FloraList).filter_by(
        park_id=park_id).all()
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('publicfloralist.html', items=items, park=park,
                               creator=creator)
    else:
        return render_template('floralist.html', items=items, park=park,
                               creator=creator)


@app.route('/park/<int:park_id>/floralist/new/', methods=['GET', 'POST'])
@login_required
def newFloraList(park_id):
    # Create a new floralist item
    park = session.query(Park).filter_by(id=park_id).one()
    if login_session['user_id'] != park.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
    to add floralist items to this park. Please create your own park in order \
    to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = FloraList(name=request.form['name'],
                            description=request.form['description'],
                            number=request.form[
            'number'], type=request.form['type'],
            park_id=park_id, user_id=park.user_id)
        session.add(newItem)
        session.commit()
        flash('New Flora %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showFlora', park_id=park_id))
    else:
        print "Hello"
        return render_template('newfloralistitem.html', park_id=park_id)


@app.route('/park/<int:park_id>/floralist/<int:floralist_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editFloraList(park_id, floralist_id):
    # Edit a floralist item
    editedItem = session.query(FloraList).filter_by(id=floralist_id).one()
    park = session.query(Park).filter_by(id=park_id).one()
    if login_session['user_id'] != park.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
                edit floralist items to this park. Please create your own park\
                in order to edit items.');}</script><body \
                onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['number']:
            editedItem.number = request.form['number']
        if request.form['type']:
            editedItem.type = request.form['type']
        session.add(editedItem)
        session.commit()
        flash('Flora Item Successfully Edited')
        return redirect(url_for('showFlora', park_id=park_id))
    else:
        return render_template('editfloralistitem.html', park_id=park_id,
                               floralist_id=floralist_id, item=editedItem)


@app.route('/park/<int:park_id>/floralist/<int:floralist_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteFloraList(park_id, floralist_id):
    # Delete a floralist item
    park = session.query(Park).filter_by(id=park_id).one()
    itemToDelete = session.query(FloraList).filter_by(id=floralist_id).one()
    if login_session['user_id'] != park.user_id:
        return "<script>function myFunction() {alert('You are not authorized \
    to delete floralist items to this park. Please create your own park in \
    order to delete items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Flora Item Successfully Deleted')
        return redirect(url_for('showFlora', park_id=park_id))
    else:
        return render_template('deleteFloraList.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'hot dog'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
