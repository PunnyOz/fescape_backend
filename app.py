from flask import Flask, flash, redirect, request, jsonify, make_response
from models import *
from tempfile import mkdtemp
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = "hi-there"  # Temporary
db.init_app(app)

with app.app_context():
    db.create_all()


def jsonMessage(message):
    # return message in JSON form
    return jsonify({'message': message})


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonMessage('a valid token is missing')

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if current_user is None:
                return jsonMessage('token is invalid')
        except:
            return jsonMessage('token is invalid')

        return f(current_user, *args, **kwargs)
    return decorator


@app.route("/register", methods=['GET', 'POST'])
def createUser():
    try:
        data = request.get_json()
    except:
        return jsonMessage('createUser unsuccessfully: Invalid JSON')
    if not data or list(data.keys()) != ['username', 'email', 'password']:
        return jsonMessage('createUser unsuccessfully: Invalid JSON')

    if len(data['password']) < 4:
        return jsonMessage('createUser unsuccessfully: Invalid password')

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), user_name=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonMessage('createUser successfully')
    except IntegrityError:
        db.session.rollback()
        return jsonMessage('createUser unsuccessfully: Username or email is already taken')


@app.route("/login", methods=["GET", "POST"])
def loginUser():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    user = User.query.filter_by(user_name=auth.username).first()
    if user is None:
        return jsonMessage('login unsuccessfully: username or password is incorrect')
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() +
                           datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route("/pdf/create", methods=['POST'])
@token_required
def createPdf(current_user):
    try:
        data = request.get_json()
    except:
        return jsonMessage('createPdf unsuccessfully: Invalid JSON')
    if not data or len(data) != 5:
        return jsonMessage('createPdf unsuccessfully: Invalid JSON')

    if Pdf_file.query.filter_by(file_name=data['file_name']).first() is not None:
        return jsonMessage('createPdf unsuccessfully: file_name is taken by another pdf_file published by you')

    newPdf = Pdf_file(user_id=current_user.id, file_name=data['file_name'], file_type=data['file_type'],
                      link=data['link'], description=data['description'])
    db.session.add(newPdf)
    db.session.commit()
    if type(data['tag']) is list:
        # still need tag validation
        pdf = Pdf_file.query.filter_by(user_id=current_user.id).filter_by(file_name=data['file_name']).first()
        db.session.add_all([Tag(pdf_id=pdf.id, tag_id=e) for e in data['tag']])
        db.session.commit()
        pass
    return jsonMessage(f"Add pdf to pdf_files")


@app.route("/admin/tag/create", methods=['POST'])
@token_required
def createTag(current_user):
    if current_user.admin == False:
        return make_response('Forbidden', 403)
    try:
        data = request.get_json()
    except:
        return jsonMessage('createPdf unsuccessfully: Invalid JSON')
    if not data or len(data) != 1:
        return jsonMessage('createPdf unsuccessfully: Invalid JSON')
    try:
        newTag = Tag_name(tag_name=data['tag_name'])
    except:
        return jsonMessage('createTag unsuccessfully: Invalid JSON')
    if Tag_name.query.filter_by(tag_name=data['tag_name']).first() is not None:
        return jsonMessage('createTag unsuccessfully: tag_name is already taken')
    db.session.add(newTag)
    db.session.commit()
    return jsonMessage(f"Create new tag called {request.json['tag_name']}")


@app.route("/admin/create", methods=['POST'])
@token_required
def createAdmin(current_user):
    if current_user.admin == False:
        return make_response('Forbidden', 403)
    try:
        data = request.get_json()
    except:
        return jsonMessage('createAdmin unsuccessfully: Invalid JSON')
    if data is None:
        return jsonMessage('createAdmin unsuccessfully: Invalid JSON')
    newAdmin = User.query.filter_by(user_name=data['username']).first()
    if newAdmin == None:
        return jsonMessage('createAdmin unsuccessfully: No user with that name')
    db.session.add(newAdmin)
    db.session.commit()
    return jsonMessage(f"Create new admin with the name {newAdmin.user_name}")


@app.route("/tag/all")
@token_required
def listTag(current_user):
    return jsonify({e.tag_id: e.tag_name for e in Tag_name.query.all()})


@app.route("/search/pdf", methods=['GET', 'POST'])
@token_required
def listTag(current_user):
    return jsonify({e.tag_id: e.tag_name for e in Tag_name.query.all()})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
