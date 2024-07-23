from flask import Flask, request, jsonify, send_from_directory,redirect,url_for ,flash, make_response
import mysql.connector
import bcrypt
from flask_mysqldb import MySQL
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
from flask_httpauth import HTTPBasicAuth
import os


app = Flask(__name__)
auth = HTTPBasicAuth()
CORS(app, resources={r"/*": {
    "origins": "*", 
    "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    "allow_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Credentials"],
    "supports_credentials": True
}})



# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "7486"
app.config["MYSQL_DB"] = "storage"
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY']= SECRET_KEY

mysql = MySQL(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check if the token is in the headers
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated




@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = app.response_class()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        return response
    if request.method == 'POST':
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        print(password, email, name) 
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt(12))
        # Connect to the MySQL database and insert the data
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO user (name,email,password) VALUES (%s,%s,%s)",(name,email,hashed_password))
        mysql.connection.commit()
        cursor.close()
        print(name,email,password)
        auth = request.authorization
       
       
        token = jwt.encode(
            {'user': name, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
            app.config['SECRET_KEY'], 
            algorithm='HS256')
        print(token)
        response= {
            "message": "Registration successful. Token saved.",
            "token": token 
        } 
        myResponse= make_response(jsonify(response), 200)
        return myResponse
       
    return send_from_directory('static','register.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.json
        email = data.get('email')
        password = data.get('password')
        print(password, email)
        cursor= mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE email= (%s)",(email,))
        user = cursor.fetchone()
        print(user)
        cursor.close()
        auth = request.authorization
        print(user[3])
        print(user[3].encode('utf-8'))
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            token = jwt.encode(
            {'user': auth.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
            app.config['SECRET_KEY'],
            algorithm='HS256')
            print(token)
            response = {
                "message": "Login successful",
                 "token":token  }
            myResponse= make_response(jsonify(response), 200)
            return myResponse
        else:
             flash("Login failed. Please check your email and password")
             return redirect(url_for('login'))
    return send_from_directory('static', 'login.html')


@app.route('/api/allusers', methods=['GET','POST'])
@token_required
def get_table_data(current_user):
    if request.method == 'GET':
        cursor =  mysql.connection.cursor()
        cursor.execute(f"SELECT * FROM user")
        rows = cursor.fetchall()
        cursor.close()
        return jsonify(rows)
    return jsonify({'message': f'Hello, {current_user}!'})




if __name__ == '__main__':
    app.run(debug=True)