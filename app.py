import datetime

from flask import Flask, request
from flask_api import FlaskAPI, status, exceptions
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from marshmallow import Schema, fields, ValidationError, pre_load

from flask import make_response, request, jsonify

app = FlaskAPI(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/pk.db"
db = SQLAlchemy(app)



##### MODELS #####


import jwt
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt


class Author(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    middle_name = db.Column(db.String(80),nullable=True)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(256), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

    def __init__(self, first_name, last_name, email, password):
        """Initialize the user with an email and a password."""
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = Bcrypt().generate_password_hash(password).decode()

    def password_is_valid(self, password):
        """
        Checks the password against it&apos;s hash to validates the user&apos;s password
        """
        return Bcrypt().check_password_hash(self.password, password)

    def save(self):
        """Save a user to the database.
        This includes creating a new user and editing one.
        """
        db.session.add(self)
        db.session.commit()

    def generate_token(self, user_id):
        """ Generates the access token"""

        try:
            # set up a payload with an expiration time
            payload = {"exp": datetime.utcnow() + timedelta(minutes=5),
                    "iat": datetime.utcnow(),
                    "sub": user_id
            }
            # create the byte string token using the payload and the SECRET key
            # jwt_string = jwt.encode(
            #     payload,
            #     current_app.config.get("SECRET"),
            #     algorithm="HS256"
            # )
            jwt_string = jwt.encode(payload)
            return jwt_string

        except Exception as e:
            # return an error in string format if an exception occurs
            return str(e)

    @staticmethod
    def decode_token(token):
        """Decodes the access token from the Authorization header."""
        try:
            # try to decode the token using our SECRET variable
            payload = jwt.decode(token, current_app.config.get("SECRET"))
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            # the token is expired, return an error string
            return "Expired token. Please login to get a new token"
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return "Invalid token. Please register or login"


class Quote(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("author.id"))
    author = db.relationship("Author", backref=db.backref("quotes", lazy="dynamic"))
    posted_at = db.Column(db.DateTime)


##### SCHEMAS #####


class AuthorSchema(Schema):
    id = fields.Int(dump_only=True)
    first_name = fields.Str()
    last_name = fields.Str()
    middle_name = fields.Str()
    email = fields.Str()
    password = fields.Str()
    # formatted_name = fields.Method("format_name", dump_only=True)
    #
    # def format_name(self, author):
    #     return "{}, {}".format(author.last, author.first)


# Custom validator
def must_not_be_blank(data):
    if not data:
        raise ValidationError("Data not provided.")


class QuoteSchema(Schema):
    id = fields.Int(dump_only=True)
    author = fields.Nested(AuthorSchema, validate=must_not_be_blank)
    content = fields.Str(required=True, validate=must_not_be_blank)
    posted_at = fields.DateTime(dump_only=True)

    # Allow client to pass author's full name in request body
    # e.g. {"author': 'Tim Peters"} rather than {"first": "Tim", "last": "Peters"}
    @pre_load
    def process_author(self, data, **kwargs):
        author_name = data.get("author")
        if author_name:
            first, last = author_name.split(" ")
            author_dict = dict(first=first, last=last)
        else:
            author_dict = {}
        data["author"] = author_dict
        return data


author_schema = AuthorSchema()
authors_schema = AuthorSchema(many=True)
quote_schema = QuoteSchema()
quotes_schema = QuoteSchema(many=True, only=("id", "content"))

##### API #####
@app.route("/login", methods=["POST"])
def login():
    try:
        # Get the user object using their email (unique to every user)
        user = Author.query.filter_by(email=request.data['email']).first()
        # Try to authenticate the found user using their password
        if user and Bcrypt().check_password_hash(user.password,request.data['password'])==True:
            response = {"message": "You logged in successfully."}
            return make_response(jsonify(response)), 200
            # Generate the access token. This will be used as the authorization header
            # access_token = user.generate_token(user.id)
            # if access_token:
            #     response = {"message": "You logged in successfully.",\
            #     "access_token": access_token.decode()}
            #     return make_response(jsonify(response)), 200
        else:
            # User does not exist. Therefore, we return an error message
            response = {"message": "Invalid email or password, Please try again."}
            return make_response(jsonify(response)), 401
    except Exception as e:
        # Create a response containing an string error message
        response = {"message": str(e)}
        # Return a server error using the HTTP Error Code 500 (Internal Server Error)
        return make_response(jsonify(response)), 500


@app.route("/authors")
def get_authors():
    authors = Author.query.all()
    # Serialize the queryset
    result = authors_schema.dump(authors)
    # return make_response(jsonify(result)), 200
    return result


@app.route("/authors", methods=["POST"])
def new_author():
    print("==========================")
    print(request.data["first_name"])
    user = Author.query.filter_by(email=request.data["email"]).first()
    if not user:
        try:
            post_data = request.data
            print("-------")
            print(post_data)
            user_obj = Author(post_data['first_name'],post_data['last_name'], post_data['email'],post_data['password'])
            # user_obj.first_name = post_data['first_name']
            # user_obj.middle_name = post_data['middle_name']
            # user_obj.last_name = post_data['last_name']
            # user_obj.email = post_data['email']
            # user_obj.password = post_data['password']
            user_obj.save()
            response = {"message": "You registered successfully. Please log in"}
            return make_response(jsonify(response)), 201
        except Exception as e:
            response = {"message": str(e)}
            return make_response(jsonify(response)), 401
    else:
        response = {"message": "User already exists. Please login."}
        return make_response(jsonify(response)), 202

@app.route("/authors/<int:pk>")
def get_author(pk):
    try:
        author = Author.query.get(pk)
    except IntegrityError:
        return {"message": "Author could not be found."}, 400
    author_result = author_schema.dump(author)
    quotes_result = quotes_schema.dump(author.quotes.all())
    return {"author": author_result, "quotes": quotes_result}


@app.route("/quotes/", methods=["GET"])
def get_quotes():
    quotes = Quote.query.all()
    result = quotes_schema.dump(quotes, many=True)
    return {"quotes": result}


@app.route("/quotes/<int:pk>")
def get_quote(pk):
    try:
        quote = Quote.query.get(pk)
    except IntegrityError:
        return {"message": "Quote could not be found."}, 400
    result = quote_schema.dump(quote)
    return {"quote": result}


@app.route("/quotes/", methods=["POST"])
def new_quote():
    json_data = request.get_json()
    if not json_data:
        return {"message": "No input data provided"}, 400
    # Validate and deserialize input
    try:
        data = quote_schema.load(json_data)
    except ValidationError as err:
        return err.messages, 422
    first, last = data["author"]["first"], data["author"]["last"]
    author = Author.query.filter_by(first=first, last=last).first()
    if author is None:
        # Create a new author
        author = Author(first=first, last=last)
        db.session.add(author)
    # Create new quote
    quote = Quote(
        content=data["content"], author=author, posted_at=datetime.datetime.utcnow()
    )
    db.session.add(quote)
    db.session.commit()
    result = quote_schema.dump(Quote.query.get(quote.id))
    return {"message": "Created new quote.", "quote": result}


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port=5000)
