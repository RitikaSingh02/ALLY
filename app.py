from flask import Flask , render_template , make_response ,  redirect , request_started , request , jsonify , session
from flask.globals import session
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required ,UserMixin
from flask_migrate import Migrate
import requests
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
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(120),unique = True ,nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)
    profile_pic_height = db.Column(db.String(200), nullable= True)
    profile_pic_width = db.Column(db.String(200), nullable= True)


class UserRequestTypes(db.Model , UserMixin):
    __tablename__ = "requestcategory"
    id =db.Column(db.Integer, primary_key=True)
    request_type_name =  db.Column(db.String(200), nullable= False)
    
    
class UserRequest(db.Model , UserMixin):
    __tablename__ = "userrequests"
    id =db.Column(db.Integer, primary_key=True)
    request_type=db.Column(db.Integer, db.ForeignKey('requestcategory.id'))
    title = db.Column(db.String(200), nullable=True)
    request_description  = db.Column(db.String(200), nullable=False)
    acc_holder_name = db.Column(db.String(200), nullable= True)
    phone = db.Column(db.String(200), nullable= True)
    ifsc = db.Column(db.String(200), nullable= True)
    acc_no = db.Column(db.String(200), nullable= True)
    upi_id = db.Column(db.String(200), nullable= True)
    gpay = db.Column(db.String(200), nullable= True)
    amazon_pay = db.Column(db.String(200), nullable= True)
    paytm = db.Column(db.String(200), nullable= True)
    phone_pay = db.Column(db.String(200), nullable= True)
    image =  db.Column(db.String(200), nullable= True)
    height = db.Column(db.String(200), nullable= True)
    width = db.Column(db.String(200), nullable= True)
    status = db.Column(db.String(200) , nullable = True)
    remark =  db.Column(db.String(200), nullable= True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
   
class UserFcms(db.Model , UserMixin):
    __tablename__ = "fcms"
    id =db.Column(db.Integer, primary_key=True)
    fcm_token = db.Column(db.String(200),unique = True , nullable=False)
    device_id = db.Column(db.String(200),unique = True , nullable=False)
    email = db.Column(db.String(200), db.ForeignKey('users.email'))    
    status = db.Column(db.String(200), default = "INSERT")
#####################################################################
#cloudinary config
import cloudinary
import cloudinary.uploader
cloudinary.config( 
  cloud_name = os.environ.get("cloud_name"),
  api_key = os.environ.get("api_key"), 
  api_secret = os.environ.get('api_secret')
)

#Cors removing func
def _build_cors_prelight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response


# def _corsify_actual_response(response):
#     response.headers.add("Access-Control-Allow-Origin", "*")
#     return response

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
            user = User.query.filter_by(email = email).first()
            if user is not None and user.is_verified is False :
                #email has to be verified
                email_verification(email)
            if User.query.filter_by(email = email).first() is not None:
                #user exists
                res['msg'] = "the user already exists return  to the login page"
                res['exists'] = 1
                res['verified'] = User.query.filter_by(email = email).first().is_verified
                if email in ['ritika.1923cs1076@kiet.edu' , 'sameer.1923co1066@kiet.edu']:
                    session['admin'] = True
                res['admin'] = session['admin']
                return jsonify(res), 401
            else:
                #register the user and login it
                res['msg'] = "new user logged in "
                res['exists'] = 0
                hashed = bcrypt.hashpw(password.encode("utf-8"),bcrypt.gensalt())
                if email.split('@')[1]!= 'kiet.edu':
                    res['msg'] = "kindly enter kiet email!!"
                    return res , 404
                if email in ['ritika.1923cs1076@kiet.edu' , 'sammerahmad.1923cs1100@kiet.edu']:
                    user = User(name = name, password=hashed , email = email , gender = gender , is_admin = True )
                    db.session.add(user)
                    db.session.commit()
                    session['admin'] = True
                else:
                    user = User(name = name, password=hashed , email = email , gender = gender )
                    db.session.add(user)
                    db.session.commit()

                user = User.query.filter_by(email = email).first()
                #call the email generator api
                if not user.is_verified:
                    #email has to be verified
                    email_verification(email)
                    return jsonify("mail sent") , 200
            return jsonify("kindly verify your email"), 404
                    

        
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
            return jsonify(res), 400
        password = data["password"]
        email = data["email"]
        user = User.query.filter_by(email = email).first()
        hashed = bcrypt.checkpw(password.encode('utf8') ,user.password.encode('utf-8'))
        print(hashed)
        if hashed:
            #login the user
            login_user(user)
            res['msg'] = "login success"
            session['admin'] = user.is_admin
            session.permanent = True
            res['admin'] = session['admin']
            return jsonify(res), 200
        else:
            res['msg'] = "Invalid credentials"
            return jsonify(res), 401

@app.route("/logout", methods=['GET'])
@login_required
def logout():
    # print(current_user.name)
    # Logout user
    logout_user()
    res = {
        'msg' : 'logout success'
    }
    return jsonify(res) , 200

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
            return jsonify(res), 400
        email = data['email']
        curr_pass = data['current_pass']
        new_pass = data['new_pass']
        hashed = bcrypt.checkpw(curr_pass.encode('utf8') ,current_user.password.encode('utf8'))
        
        if hashed:
            new_pass_hashed = bcrypt.hashpw(new_pass.encode("utf-8"),bcrypt.gensalt())
            query = User.query.filter_by(email = email).update(dict(password = new_pass_hashed))
            db.session.commit()
            res['msg'] = "change password successfull"
            return  jsonify(res), 200
        res['msg'] = "enter correct original pass"
        return  jsonify(res), 200

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
            res['profile_pic'] = current_user.profile_pic
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

def email_verification(email):   
    msg = Message('Kindly Verify Your Email To Proceed', sender = os.environ.get('MAIL'), recipients = [email])
    msg.body = "This is the email body"
    id = '1'
    msg.attach('mail.png','image/gif',open('./static/mail.png', 'rb').read(), 'inline', headers=[['Content-ID','<id>'],])
    #call the otp generator
    otp = otp_generater(email)
    msg.html = render_template('verify.html' , otp=otp , id = '<'+id+'>')
    mail.send(msg)
    
@app.route("/verify", methods = ['POST'])
def verify():
    data = request.get_json(force=True)      
    email = data['email']
    otp = data['otp']
    user = User.query.filter_by(email = email).first()
    res = {}
    res['msg'] = "not verified"
    res['verified'] = user.is_verified
    if (check(email , otp)):
            user.is_verified = True
            db.session.commit()
            res['msg'] = "verified"
            res['verified'] = user.is_verified
            return jsonify(res), 200
    return jsonify(res), 404
    
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
@app.route('/profile_pic_upload' , methods = ['POST'])     
def profile_pic():
    file = request.files['file']
    email = current_user.email
    res = {}
    res['msg'] = "failed"
    res['url'] = ""
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_result = cloudinary.uploader.upload(file)
        print(upload_result)
        user = User.query.filter_by(email = email).first()
        user.profile_pic = upload_result['url']
        user.profile_pic_height = upload_result['height']
        user.profile_pic_width = upload_result['width']
        db.session.commit()
        res['msg'] = "success"
        res['url'] = upload_result['url']
        res['height'] = upload_result['height']
        res['width'] = upload_result['width']
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify(res) , 200
    return jsonify(res) , 400

@login_required
@app.route('/upload' , methods = ['POST'])     
def upload_file():
    file = request.files['file']
    email = current_user.email
    res = {}
    res['msg'] = "failed"
    res['url'] = ""
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        upload_result = cloudinary.uploader.upload(file)
        # user = User.query.filter_by(email = email).first()
        # user.profile_pic = upload_result['url']
        # db.session.commit()
        res['msg'] = "success"
        res['url'] = upload_result['url']
        res['height'] = upload_result['height']
        res['width'] = upload_result['width']
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify(res) , 200
    return jsonify(res) , 400

@login_required
@app.route("/request_category", methods = ['GET'])
def request_category():
    res = []
    categories = UserRequestTypes.query.all()
    for category in categories:
        id = category.id
        name = category.request_type_name
        l = [id , name]
        res.append(l)
    return jsonify(res) , 200
@login_required
@app.route("/request_help", methods = ['POST'])
def request_help():
    if request.method == 'POST':
        # print(request.files.getlist)
        data = request.get_json(force=True)  
        upi_id = data['upi_id']
        acc_no = data['acc_no']
        acc_holder_name = data['acc_holder_name']
        category_help = data['category_help']
        request_description = data['description']
        title = data['title']
        ifsc = data['ifsc']
        phone = data['phone']
        gpay = data['gpay']
        amazon_pay = data['amazon_pay']        
        paytm = data['paytm']        
        phone_pay = data['phone_pay']
        image = data['file']
        image_height=data['height']
        image_width=data['width']
        res = {}
        user = UserRequest(request_type = category_help , 
                           title = title,
                           request_description = request_description , 
                           acc_holder_name = acc_holder_name,
                           phone = phone,
                           ifsc = ifsc,
                           acc_no = acc_no,
                           upi_id = upi_id,
                           gpay = gpay,
                           amazon_pay = amazon_pay,
                           paytm = paytm,
                           phone_pay = phone_pay,
                           image = image,
                           height = image_height,
                           width = image_width,
                           status = "PENDING",
                           user_id = current_user.id)
        db.session.add(user)
        db.session.commit()
        res['msg'] = "success"
        return jsonify(res) , 200   
##############################3########33

##notifications section##
@login_required
@app.route('/fcm-insert' , methods = ['POST'])
def fcm_insert():
    res = {}
    data = request.get_json(force=True)  
    fcm_token = data['fcm_token']
    device_id = data['device_id']
    email = data['email']
    fcm = UserFcms.query.filter_by(fcm_token = fcm_token).first()
    if fcm is not None:
        fcm.status = "INSERT"
        db.session.commit()
    else:
        fcm = UserFcms(fcm_token = fcm_token , device_id = device_id , email = email , status = "INSERT")
        db.session.add(fcm)
        db.session.commit()
    res['msg'] = "fcm inserted"
    return jsonify(res), 200
    
@login_required
@app.route('/fcm-delete' , methods = ['POST'])
def fcm_del():
    res = {}
    data = request.get_json(force=True)
    fcm_token = data['fcm_token']
    device_id = data['device_id']
    fcm = UserFcms.query.filter_by(fcm_token = fcm_token , device_id = device_id).first()
    fcm.status = "DELETE"
    db.session.commit()
    res['msg'] = "fcm deleted successfully"
    return jsonify(res) , 200
import subprocess

@login_required
@app.route('/notifications' , methods = ['GET'])
def notification():
    email =  current_user.email
    fcm_token = UserFcms.query.filter_by(email = email).first().fcm_token
    userdata = {"fcm":fcm_token , "body" : "Your Ally is calling :)" , "image" :"https://res.cloudinary.com/riz0000000001/image/upload/v1626701718/ra3zaagudnzvmfttwqeb.png"}
    resp = requests.post('https://warm-forest-06132.herokuapp.com', params=userdata)
    return jsonify('notification sent' ) , 200

def notify(fcm_token ,msg , image):
    userdata = {"fcm":fcm_token , "body" :msg , "image" :image}
    resp = requests.post('https://warm-forest-06132.herokuapp.com', params=userdata)
###aadmin panel###
@login_required
@app.route('/pending_requests' , methods = ['GET'])
def pending_requests():
    request_all = UserRequest.query.filter_by(status = "PENDING").all()
    res = []
    for req in request_all:
        res.append(
            {
                "request_id" :req.id ,
                "request_title" :req.title , 
                "request_description":req.request_description ,
                "request_type":req.request_type,
                "acc_holder_name":req.acc_holder_name , 
                "phone" :req.phone,
                "ifsc": req.ifsc,
                "user_id": req.user_id,
                "acc_no" : req.acc_no,
                "upi_id":req.upi_id,
                "paytm": req.paytm,
                "phone_pay":req.phone_pay,
                "image":req.image,
                "image_height":req.height,
                "image_width":req.width
            }
        )
    return jsonify(res) , 200

@login_required
@app.route('/requests_status_update' , methods = ['POST'])
def requests_status():
    data = request.get_json(force=True)
    request_id = data['id']
    request_status = data['status']
    remark = data["remark"]
    req = UserRequest.query.filter_by(id = request_id).first()
    req.status = request_status
    req.remark = remark
    db.session.commit()
    res= {'msg' : "Your help request is" + request_status}
    if(request_status == "ACCEPTED"):
        for user in User.query.all():
            if((user.id == current_user.id)):
                notify(user , res['msg'] , req.image)
            else:
                notify(user ,"Somebody needs your help :)" , "http://res.cloudinary.com/riz0000000001/image/upload/v1626701718/ra3zaagudnzvmfttwqeb.png")
            
    return res , 200

@login_required
@app.route('/posts' , methods = ["GET"])
def posts():
    res = []
    posts = UserRequest.query.filter_by(status = "APPROVED").all()
    for req in posts:
        res.append(
                {
                "request_id" :req.id ,
                "request_title" :req.title , 
                "request_description":req.request_description ,
                "request_type":req.request_type,
                "acc_holder_name":req.acc_holder_name , 
                "phone" :req.phone,
                "ifsc": req.ifsc,
                "user_id": req.user_id,
                "user_name": User.query.filter_by(id = req.user_id).first().name,
                "acc_no" : req.acc_no,
                "upi_id":req.upi_id,
                "paytm": req.paytm,
                "phone_pay":req.phone_pay,
                "image":req.image,
                "image_ht":req.height,
                "image_width":req.width,
                "amazon_pay":req.amazon_pay,
                "gpay":req.gpay
            }
        )
    return jsonify(res) , 200
@login_required
@app.route('/my_requests' , methods = ["GET"])
def my_requests():
    res = []
    user_req = UserRequest.query.filter_by(user_id = current_user.id).all()
    for req in user_req:
        res.append(
                {
                "request_id" :req.id ,
                "request_title" :req.title , 
                "request_description":req.request_description ,
                "request_type":req.request_type,
                "acc_holder_name":req.acc_holder_name , 
                "phone" :req.phone,
                "ifsc": req.ifsc,
                "user_id": req.user_id,
                "user_name": User.query.filter_by(id = req.user_id).first().name,
                "acc_no" : req.acc_no,
                "upi_id":req.upi_id,
                "paytm": req.paytm,
                "phone_pay":req.phone_pay,
                "image":req.image,
                "image_ht":req.height,
                "image_width":req.width,
                "amazon_pay":req.amazon_pay,
                "gpay":req.gpay
            }
        )
    return jsonify(res) , 200
            
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port=8080)

