from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

app = FlaskAPI(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/test.db"

# Order matters: Initialize SQLAlchemy before Marshmallow
db = SQLAlchemy(app)
ma = Marshmallow(app)

# from marshmallow import Model, Column, Integer, String, DateTime


class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    author_id = db.Column(db.Integer, db.ForeignKey("author.id"))
    author = db.relationship("Author", backref="books")

class AuthorSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Author

    id = ma.auto_field()
    name = ma.auto_field()
    books = ma.auto_field()


class BookSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Book
        include_fk = True


class UserSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("email", "date_created", "_links")

    # Smart hyperlinking
    _links = ma.Hyperlinks(
        {"self": ma.URLFor("user_detail", id="<id>"), "collection": ma.URLFor("users")}
    )


user_schema = UserSchema()
users_schema = UserSchema(many=True)


db.create_all()
author_schema = AuthorSchema()
book_schema = BookSchema()
author = Author(name="Chuck Paluhniuk")
book = Book(title="Fight Club", author=author)
db.session.add(author)
db.session.add(book)
db.session.commit()
author_schema.dump(author)

from pprint import pprint



@app.route("/")
def users():
    authors = Author.query.all()
    result = authors_schema.dump(authors)
    return {"authors": result}
#
#
# @app.route("/api/users/<id>")
# def user_detail(id):
#     user = User.get(id)
#     return user_schema.dump(user)


# {
#     "email": "fred@queen.com",
#     "date_created": "Fri, 25 Apr 2014 06:02:56 -0000",
#     "_links": {
#         "self": "/api/users/42",
#         "collection": "/api/users/"
#     }
# }


# notes = {
#     0: 'do the shopping',
#     1: 'build the codez',
#     2: 'paint the door',
# }
#
# def note_repr(key):
#     return {
#         'url': request.host_url.rstrip('/') + url_for('notes_detail', key=key),
#         'text': notes[key]
#     }
#
#
# @app.route("/", methods=['GET', 'POST'])
# def notes_list():
#     """
#     List or create notes.
#     """
#     if request.method == 'POST':
#         note = str(request.data.get('text', ''))
#         idx = max(notes.keys()) + 1
#         notes[idx] = note
#         return note_repr(idx), status.HTTP_201_CREATED
#
#     # request.method == 'GET'
#     return [note_repr(idx) for idx in sorted(notes.keys())]
#
#
# @app.route("/<int:key>/", methods=['GET', 'PUT', 'DELETE'])
# def notes_detail(key):
#     """
#     Retrieve, update or delete note instances.
#     """
#     if request.method == 'PUT':
#         note = str(request.data.get('text', ''))
#         notes[key] = note
#         return note_repr(key)
#
#     elif request.method == 'DELETE':
#         notes.pop(key, None)
#         return '', status.HTTP_204_NO_CONTENT
#
#     # request.method == 'GET'
#     if key not in notes:
#         raise exceptions.NotFound()
#     return note_repr(key)


if __name__ == "__main__":
    app.run(debug=True)
