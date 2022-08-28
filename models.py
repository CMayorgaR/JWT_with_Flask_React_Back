from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, true

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return "<User %r>" % self.email

    def serialize(self):
        return{
            "id": self.id,
            "email": self.email
        }