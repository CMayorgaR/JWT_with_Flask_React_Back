import os
import re
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_cors import CORS
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import db, User

BASEDIR = os.path.abspath(os.path.dirname(__file__))
app = Flask (__name__)
db.init_app(app)
CORS(app)
Migrate (app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(BASEDIR, "test.db") #Dirección provisoria de la base de datos
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'secret-key' #Bcrypt
app.config['JWT_SECRET_KEY'] = 'even-more-secret-key' #JWT

email_regEx = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
password_regEx = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"

@app.route('/sign_up', methods=['POST'])
def create_user():
    password= request.json.get('password')
    email= request.json.get('email')
    if email != '' and re.search(email_regEx, email):
        user = User.query.filter_by(email=email).first()
        if user is not None:
            return jsonify({
                'Error':'User already exists or wrong email format'
            }), 400
        else:
            if password != '' and re.search(password_regEx, password): #validación contraseña no puede ser vacía y debe cumplir con recomendaciones de formato de expresión regular
                user= User()
                user.email = email
                password_hash= bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
                user.password = password_hash #guardo la encriptación de la contraseña

                db.session.add(user)
                db.session.commit()

                return jsonify(
                    'User successfully created'
                ), 200
            else:
                return jsonify({
                    'Error':'Wrong password format'
                }), 400
    else:
        return jsonify({
            'Error':'There is a problem with the registration'
        }), 400


@app.route ('/delete_user/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify('Usuario eliminado exitosamente')


@app.route ('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    if password == '' and email == '':
        return ({
            'Error': 'Wrong email or password'
        }), 400
    else:
        user = User.query.filter_by(email=email).first()
        if user is not None:
            check_password = bcrypt.check_password_hash(user.password, password)
            if check_password:
                access_token = create_access_token(identity=email)
                return jsonify({
                    'user': user.serialize(),
                    'access_token': access_token
                }), 200
            else:
                return ({
                    'Error': 'Invalid email or password'
                }), 400
        else:
            return ({
                    'Error': 'User is not registered. Please sign up'
                }), 400

if __name__ == '__main__':
    app.run(host='localhost', port=8080)