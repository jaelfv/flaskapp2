from flask import Flask
from flask import Flask, make_response,request 
from flask_pymongo import PyMongo
from flask import abort, jsonify, redirect, render_template
from flask import request, url_for
from forms import ProductForm
from flask_login import LoginManager, current_user,login_required
from flask_login import login_user, logout_user
from forms import LoginForm
from models import User

import json

app = Flask(__name__)

app.config.from_pyfile('settings.cfg')


mongo = PyMongo(app)

@app.route('/login/', methods=['GET', 'POST'])
def login():
  if current_user.is_authenticated:
    return redirect(url_for('products_list'))
  form = LoginForm(request.form)
  error = None
  if request.method == 'POST' and form.validate():
    username = form.username.data.lower().strip()
    password = form.password.data.lower().strip()
    user = mongo.db.users.find_one({"username": form.username.data})
    if user and User.validate_login(user['password'], form.password.data):  
      user_obj = User(user['username'])
      login_user(user_obj)
      return redirect(url_for('products_list'))
    else:
      error = 'Incorrect username or password.'
  return render_template('user/login.html',
      form=form, error=error)

@app.route('/logout/')
def logout():
  logout_user()
  return redirect(url_for('products_list'))

@app.route('/')
def index():
  return redirect(url_for('products_list'))


@app.route('/products/')
def products_list():
  """Provide HTML listing of all Products."""
  # Query: Get all Products objects, sorted by date.
  products = mongo.db.products.find()[:]
  return render_template('product/index.html',
    products=products)

from bson.objectid import ObjectId

@app.route('/products/<product_id>/')
def product_detail(product_id):
  """Provide HTML page with a given product."""
  # Query: get Product object by ID.
  product = mongo.db.products.find_one({ "_id": ObjectId(product_id) })
  print (product)
  if product is None:
    # Abort with Not Found.
    abort(404)
  return render_template('product/detail.html',
    product=product)

@app.route( 
  '/products/<product_id>/edit/', methods=['GET', 'POST'])
@login_required
def product_edit(product_id):
  product = mongo.db.products.find_one({ "_id": ObjectId(product_id) })
  if product is None:
        # Abort with Not Found.
    abort(404)    
  form = ProductForm(request.form)
  if request.method == 'POST' and form.validate():
    mongo.db.products.replace_one({"_id": ObjectId(product_id)},form.data)
    # Success. Send user back to full product list.
    return redirect(url_for('products_list'))
  # Either first load or validation error at this point.
  return render_template('product/editold.html', form=form, product=product)
  


@app.route('/products/<product_id>/delete/', methods=['DELETE'])
@login_required
def product_delete(product_id):
  """Delete record using HTTP DELETE, respond with JSON."""
  result = mongo.db.products.delete_one({ "_id": ObjectId(product_id) })
  if result.deleted_count == 0:
    # Abort with Not Found, but with simple JSON response.
    response = jsonify({'status': 'Not Found'})
    response.status = 404
    return response
  return jsonify({'status': 'OK'})

@app.route('/products/create/', methods=['GET', 'POST'])
@login_required
def product_create():
  """Provide HTML form to create a new product."""
  form = ProductForm(request.form)
  if request.method == 'POST' and form.validate():
    mongo.db.products.insert_one(form.data)
    # Success. Send user back to full product list.
    return redirect(url_for('products_list'))
  # Either first load or validation error at this point.
  return render_template('product/edit.html', form=form)


@app.route('/string/')
def return_string():
  dump = dump_request_detail(request)
  return 'Hello, world!'

@app.route('/object/')
def return_object():
  dump = dump_request_detail(request)
  headers = {'Content-Type': 'text/plain'}
  return make_response(Response('Hello, world! \n' + dump, status=200,
    headers=headers))

@app.route('/tuple/<path:resource>')
def return_tuple(resource):
  dump = dump_request_detail(request)
  return 'Hello, world! \n' + dump, 200, {'Content-Type':
    'text/plain'}


def dump_request_detail(request):
  request_detail = """
## Request INFO ##
request.endpoint: {request.endpoint}
request.method: {request.method}
request.view_args: {request.view_args}
request.args: {request.args}
request.form: {request.form}
request.user_agent: {request.user_agent}
request.files: {request.files}


## request.headers ##
{request.headers}
  """.format(request=request).strip()
  return request_detail

@app.before_request
def callme_before_every_request():
  # Demo only: the before_request hook.
  app.logger.debug(dump_request_detail(request))

@app.after_request
def callme_after_every_response(response):
  # Demo only: the after_request hook.
  app.logger.debug('# After request #\n' + repr(response))
  return response

import bson

@app.errorhandler(404)
def error_not_found(error):
  return render_template('error/not_found.html'), 404

@app.errorhandler(bson.errors.InvalidId)
def error_not_found(error):
  return render_template('error/not_found.html'), 404

@app.errorhandler(401)
def error_Unauthorized(error):
  return render_template('error/Unauthorized.html'), 401

@app.errorhandler(403)
def error_Forbidden(error):
  return render_template('error/Forbidden.html'), 403

@app.errorhandler(400)
def error_Bad_Request(error):
  return render_template('error/Bad_Request.html'), 400

@app.errorhandler(500)
def error_Server_Error(error):
  return render_template('error/Server_Error.html'), 500

@app.errorhandler(405)
def error_not_allowed(error):
  return render_template('error/not_allowed.html'), 405


app.config['SECRET_KEY'] = 'secretkey2020' # Create your own.
app.config['SESSION_PROTECTION'] = 'strong'

# Use Flask-Login to track current user in Flask's session.
login_manager = LoginManager()
login_manager.setup_app(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
  """Flask-Login hook to load a User instance from ID."""
  u = mongo.db.users.find_one({"username": user_id})
  if not u:
        return None
  return User(u['username'])


if __name__ == '__main__':
    app.run(host='0.0.0.0')