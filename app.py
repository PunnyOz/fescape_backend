import sqlite3
from flask import Flask, flash, redirect, request, session, jsonify
from models import *
from tempfile import mkdtemp
import os
import hashlib

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/users/create", methods=['POST'])
def createUser():
    user = User.query.filter_by(user_name=request.json['user_name']).first()
    if user != None:
        return "Username taken"
    key = hashlib.sha256(request.json['hash_pass'].encode()).hexdigest()
    newUser = User(user_name=request.json['user_name'], hash_pass=key)
    db.session.add(newUser)
    db.session.commit()
    return f"Add Account \n Username:{request.json['user_name']}\n Hashpass:{request.json['hash_pass']}"


@app.route("/users/check", methods=['POST'])
def checkUser():
    key = hashlib.sha256(request.json['hash_pass'].encode()).hexdigest()
    user = User.query.filter_by(user_name=request.json['user_name']).filter_by(hash_pass=key).first()
    if user:
        return "True"
    return "False"


@app.route("/pdf/create", methods=['POST'])
def createPdf():
    newPdf = Pdf_file(user_id=request.json['user_id'], file_name=request.json['file_name'], file_type=request.json['file_type'],
                      link=request.json['link'], description=request.json['description'])
    db.session.add(newPdf)
    if request.json['tag']:
        pass
    db.session.commit()
    return f"Add pdf to pdf_files"


@app.route("/tag/create", methods=['POST'])
def createTag():
    newTag = Tag_name(tag_name=request.json['tag_name'])
    db.session.add(newTag)
    db.session.commit()
    return f"Create new tag called {request.json['tag_name']}"


@app.route("/tag/all")
def listTag():
    return jsonify({e.tag_id: e.tag_name for e in Tag_name.query.all()})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
