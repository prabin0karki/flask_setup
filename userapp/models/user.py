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
