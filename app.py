from flask import Flask , render_template , make_response ,  redirect , request_started , request , jsonify , session
from flask.globals import session
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required ,UserMixin
from flask_migrate import Migrate

import os
import json
import bcrypt
from werkzeug.utils import secure_filename
from flask import send_from_directory
from dotenv import load_dotenv
load_dotenv('./.env')

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db , compare_type=True , render_as_batch = True)
# Initialize login manager
login = LoginManager(app)
login.init_app(app)  # configuring the app for Flask-Login

@login.user_loader
def load_user(user_id):
    return User.query.get(user_id)
# It should return None (not raise an exception) if the ID is not valid.

#error handling
@app.errorhandler(404)
def not_found(e):
    # defining function
    return "unauthorized!" ,404
@app.errorhandler(405)
def not_found(e):
    # defining function
    return "method not allowed" , 405


############################################3#models#######################################3
class User(db.Model , UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), nullable=False)
    gender = db.Column(db.String(25),  nullable=False)
    password = db.Column(db.String(), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(120),unique = True ,nullable=False)
#####################################################################


#Cors removing func
def _build_cors_prelight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response


def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

#####################################################################################################################
##########################################################################################################
#############################################################################################################################################################
##########################################################################################################
##########################################################################################################
#Email OTP Section
email_dict= {}
import random
def otp_generater(email):
    otp = random.randint(1000, 9999)#genrate otp
    print("to be very " , otp)
    if email not in email_dict:
        email_dict[email] = []
    email_dict[email].append(otp)
    return otp

def check(email , otp):
    print(otp , email)
    if email in email_dict and email_dict[email].pop(0) == int(otp):
        print("yay! you are verified")
        return True
    return False

#routes
@app.route('/index', methods=['POST'])
def index():
    # print(request.method=='POST')
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    else:
        if request.method == 'POST':
            print(request.get_json(force=True))
            data = request.get_json(force=True)
            name = data["name"]
            gender = data["gender"]
            password = data["password"]
            email = data["email"]
            session['admin'] = False
            
            res = {}
            # user_object = User.query.filter_by(password=password ,email = email).first()
            
            if User.query.filter_by(email = email).first() is not None:
                #user exists
                res['msg'] = "the user already exists return  to the login page"
                res['exists'] = 1
                if email in ['ritika.1923cs1076@kiet.edu' , 'sameer.1923co1066@kiet.edu']:
                    session['admin'] = True
                res['admin'] = session['admin']
                return _corsify_actual_response(jsonify(res)), 401
            else:
                #register the user and login it
                res['msg'] = "new user logged in "
                res['exists'] = 0
                #call the email generator api
                if 'otp' not in data:
                    return "kindly verify your email" , 404
                else:
                    #email has been verified!
                    hashed = bcrypt.hashpw(password.encode("utf-8"),bcrypt.gensalt())
                    print(hashed)
                    if email.split('@')[1]!= 'kiet.edu':
                        res['msg'] = "kindly enter kiet email!!"
                        return res , 404
                    if email in ['ritika.1923cs1076@kiet.edu' , 'sammerahmad.1923cs1100@kiet.edu']:
                        user = User(name = name, password=hashed , email = email , gender = gender , is_admin = True)
                        session['admin'] = True
                    else:
                        user = User(name = name, password=hashed , email = email , gender = gender)
                    db.session.add(user)
                    db.session.commit()
                    login_user(user)
                    res['admin'] = session['admin']
                    
                    return _corsify_actual_response(jsonify(res)), 200
        
@app.route('/login', methods=['POST'])
def login():
        # print(request)
    res = {}
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    else:
        print(request.get_json(force=True))
        data = request.get_json(force=True)
        if 'email' not in data or 'password' not in data:
            res['msg'] = 'Bad Request'
            return _corsify_actual_response(jsonify(res)), 400
        password = data["password"]
        email = data["email"]
        user = User.query.filter_by(email = email).first()
        hashed = bcrypt.checkpw(password.encode('utf8') ,user.password)
        print(hashed)
        if hashed:
            #login the user
            login_user(user)
            res['msg'] = "login success"
            return _corsify_actual_response(jsonify(res)), 200
        else:
            res['msg'] = "Invalid credentials"
            return _corsify_actual_response(jsonify(res)), 401

@app.route("/logout", methods=['GET'])
@login_required
def logout():
    # print(current_user.name)
    # Logout user
    logout_user()
    res = {
        'msg' : 'logout success'
    }
    return res , 200

@app.route("/passwordchange", methods=[ 'POST'])
@login_required
def change_password():
    #endpoint to change pass  
    res = {}
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    else:
        print(request.get_json(force=True))
        data = request.get_json(force=True)      
        if 'email' not in data or 'current_pass' not in data or 'new_pass' not in data:
            res['msg'] = 'Bad Request'
            return _corsify_actual_response(jsonify(res)), 400
        email = data['email']
        curr_pass = data['current_pass']
        new_pass = data['new_pass']
        hashed = bcrypt.checkpw(curr_pass.encode('utf8') ,current_user.password)
        
        if hashed:
            new_pass_hashed = bcrypt.hashpw(new_pass.encode("utf-8"),bcrypt.gensalt())
            query = User.query.filter_by(email = email).update(dict(password = new_pass_hashed))
            db.session.commit()
            res['msg'] = "change password successfull"
            return  _corsify_actual_response(jsonify(res)), 200
        res['msg'] = "enter correct original pass"
        return  _corsify_actual_response(jsonify(res)), 200

@app.route('/profile', methods=[ 'GET'])
@login_required
def profile():
        # print(request)
    res = {}
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    else:
        if request.method == "GET":  # CORS preflight
            res['name'] = current_user.name
            res['gender'] = current_user.gender
            res['email'] = current_user.email
            return res , 200
        
###################Sending mails##################3
from flask_mail import Mail, Message
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL')
app.config['MAIL_PASSWORD'] = os.environ.get('PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
@app.route("/mail" , methods = ['POST'])
def email_verification():   
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    else:
        data = request.get_json(force=True)      
        email = data['email']
        msg = Message('Kindly Verify Your Email To Proceed', sender = os.environ.get('MAIL'), recipients = [email])
        msg.body = "This is the email body"
        id = '1'
        msg.attach('mail.png','image/gif',open('./static/mail.png', 'rb').read(), 'inline', headers=[['Content-ID','<id>'],])
        #call the otp generator
        otp = otp_generater(email)
        msg.html = render_template('verify.html' , otp=otp , id = '<'+id+'>')
        mail.send(msg)
        return "Sent"
    
@app.route("/verify", methods = ['POST'])
def verify():
    data = request.get_json(force=True)      
    email = data['email']
    otp = data['otp']
    if request.method == "OPTIONS":  # CORS preflight
        return _build_cors_prelight_response()
    elif (check(email , otp)):
        return "verified redirect to the home page / login succes" , 200
    return "kindly enter correct otp" , 404
###################################333
###################################333
###################################333
##############request help section#############
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)
       
@login_required
@app.route("/request_help", methods = ['POST'])
def request_help():
    if request.method == 'POST':
        print(request.files.getlist)
        data = request.get_json(force=True)  
        upi_id = data['upi_id']
        acc_no = data['acc_no']
        acc_holder_name = data['acc_holder_name']
        category_help = data['category_help']
        ifsc = data['ifsc']
        if 'phone' in data:
            phone = data['phone']
        if 'gpay' in data:
            gpay = data['gpay']
        if 'amazon_pay' in data:
            amazon_pay = data['amazon_pay']        
        if 'paytm' in data:
            paytm = data['paytm']        
        if 'phone_pay' in data:
            phone_pay = data['phone_pay']
        print(upi_id , acc_no , acc_holder_name , ifsc  , category_help)
        if 'file' in request.files:
            file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return 'file uploaded successfully'
        return "invalid file format"
##############################3########33

##notifications section##
@login_required
@app.route('/notifications' , methods = ['GET'])
def notification():
    return render_template('notification.html') , 200
    
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port=8080)

