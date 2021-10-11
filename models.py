from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String, nullable=False)
    hash_pass = db.Column(db.String, nullable=False)


class Pdf_file(db.Model):
    __tablename__ = "pdf_files"
    pdf_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    file_name = db.Column(db.String, nullable=False)
    file_type = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)


class Tag_name(db.Model):
    __tablename__ = "tag_names"
    tag_id = db.Column(db.Integer, primary_key=True)
    tag_name = db.Column(db.String, nullable=False)


class Tag(db.Model):
    __tablename__ = "tag"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey("tag_names.tag_id"), nullable=False)
