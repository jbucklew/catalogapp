import random
import string
import json
import requests
import httplib2

from flask import Flask, render_template, jsonify, url_for, abort, g
from flask import request, jsonify, redirect, make_response, flash
from flask import session as login_session

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import AccessTokenCredentials
from oauth2client.client import FlowExchangeError

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, User, Category, CategoryItem


# load client_secrets file used by google's oauth2 login
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Catalog Application'

app = Flask(__name__)

# set up database and session to interface with the sqlite database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# show the login page using a google oauth2 login
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, CLIENT_ID=CLIENT_ID)


# handles everything required by the google oauth2 login.
# this is pretty much from the udactiy course
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.heaaders['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exists, if not create a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    if login_session['username']:
        flash("Welcome %s You are now logged in." % login_session['username'],
              'msg')
    else:
        flash("Welcome. You are now logged in.", 'msg')

    return 'success'


# logout and delete all user information from session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        print('Access Token is None')
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s' %
           login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash('You have been logged out.')
        return redirect('/catalog')

    else:
        flash('Failed to revoke token for given user', 'error')
        return redirect('/catalog')


# main page show the list of defined categories and the most recent
# items added.
@app.route('/')
@app.route('/catalog')
def showCategories():
    user_logged_in = False
    username = ''

    # if user is logged it they will be allowed to add categories and
    # add and edit items. Also used to determine to show either the
    # login or logout button
    if 'username' in login_session:
        user_logged_in = True
        username = login_session['username']

    # get categories and items to display
    categories = session.query(Category)
    # show the number most recent items that match the number of categories
    num = categories.count()
    latest_items = session.query(CategoryItem,
                                 Category).join(Category).limit(num)

    return render_template('categories.html', categories=categories,
                           latest_items=latest_items,
                           user_logged_in=user_logged_in)


# add a new category
@app.route('/catalog/category/new', methods=['GET', 'POST'])
def newCategory():
    # only allow a category to be created if the user is logged in.
    if 'username' not in login_session:
        return redirect('/login')

    # a post request indicates a new category is being submitted
    if request.method == 'POST':
        category_name = request.form['name']
        new_category = Category(name=category_name,
                                user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('Category %s successfully added.' % category_name, 'msg')
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))
    else:
        # a get request displays the form page to add a new category
        return render_template('newcategory.html')


# show items for the selected category
@app.route('/catalog/<category_name>/items')
def showCategoryItems(category_name):
    user_logged_in = False

    # if the user is logged in, show the logout button else the login
    # button will be shown
    if 'username' in login_session:
        user_logged_in = True

    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CategoryItem).filter_by(category_id=category.id)
    return render_template('categoryitems.html', category=category,
                           items=items, categories=categories,
                           user_logged_in=user_logged_in)


# add an item to the selected category
@app.route('/catalog/<category_name>/new', methods=['GET', 'POST'])
def newItem(category_name):
    # only allow a category to be created if the user is logged in.
    if 'username' not in login_session:
        return redirect('/login')

    # a post request indicates a new item is being submitted
    if request.method == 'POST':
        # need category id to build the correct association
        category = session.query(Category).filter_by(name=category_name).one()
        newItem = CategoryItem(name=request.form['name'],
                               description=request.form['description'],
                               category_id=category.id,
                               user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('Item %s successfully added.' % request.form['name'], 'msg')
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))

    else:
        # a get request displays the form page to add a new item
        return render_template('newitem.html', category_name=category_name)


# show item information for selected category
@app.route('/catalog/<category_name>/<item_name>')
def showItem(category_name, item_name):
    # Will need the category id to make sure we have the right item
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(category_id=category.id,
                                                 name=item_name).one()

    # since users can only edit/delete items they created, can_edit
    # will indicated if the selected item is one they can edit.
    can_edit = False
    user_logged_in = False

    # if user logged in show logout button else show login button
    if 'username' in login_session:
        user_logged_in = True

        # if the user is logged in and they created the selected item
        # the edit and delete buttons will be displayed.
        if item.user_id == login_session['user_id']:
            can_edit = True

    return render_template('item.html', category_name=category.name, item=item,
                           user_logged_in=user_logged_in, can_edit=can_edit)


# delete selected item
@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    # an item can only be deleted if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')

    user_logged_in = True

    # Will need the category id to make sure we have the right item
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(category_id=category.id,
                                                 name=item_name).one()

    # if user did not create item do not allow delete
    if item.user_id != login_session['user_id']:
        flash('You are not authorized to delete this item', 'error')
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))

    # a post indicates an item to be deleted
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item %s deleted.' % item_name, 'msg')
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))
    else:
        # a get request will display the delete item form
        return render_template('deleteitem.html',
                               category_name=category_name,
                               item_name=item_name,
                               user_logged_in=user_logged_in)


# edit an item for the selected category
@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_name):
    # only allow edits for logged in users
    if 'username' not in login_session:
        return redirect('/login')

    user_logged_in = True

    # Will need the category id to make sure we have the right item
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(category_id=category.id,
                                                 name=item_name).one()

    # if user did not create item return error
    if item.user_id != login_session['user_id']:
        flash('You can only edit items you created.', 'error')
        return redirect(url_for('showCategoryItems',
                                category_name=category_name))

    # a post method indicates an edit to the current item
    if request.method == 'POST':
        # determine which values have changed
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            item.category_id = request.form['category']

        session.add(item)
        session.commit()
        flash('Item %s successfully changed' % item_name, 'msg')

        # need new category name if it was changed
        category = session.query(Category).filter_by(id=item.category_id).one()
        return redirect(url_for('showItem', category_name=category.name,
                                item_name=item.name))
    else:
        # a get request will show the edit item form
        categories = session.query(Category).all()
        return render_template('edititem.html', item=item,
                               category=category,
                               categories=categories,
                               user_logged_in=user_logged_in)


# add a new user to the user table in the database
def createUser(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# get user information from user table using the user's id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# get the user's id from user table using the user's email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON API endpoints

# return the list of categories in json format
@app.route('/catalog/json')
def categoriesJSON():
    categories = session.query(Category).order_by(Category.name.asc())
    return jsonify(Categories=[c.serialize for c in categories])


# return the selected item information in json format
@app.route('/catalog/<category_name>/<item_name>/json')
def showItemJSON(category_name, item_name):
    # Will need the category id to make sure we have the right item
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CategoryItem).filter_by(category_id=category.id,
                                                 name=item_name)
    return jsonify(Item=[i.serialize for i in item])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
