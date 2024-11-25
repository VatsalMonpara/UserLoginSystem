from passlib.context import CryptContext
from database.database import Sessionlocal
from src.models.users import User, OTP
from fastapi import HTTPException
import random
import uuid


db = Sessionlocal()

#  check for same username
def find_same_username(username:str):
    find_same_username = db.query(User).filter(User.username == username).first()
    
    if find_same_username:
        if find_same_username.is_active == True:
            raise HTTPException(status_code=400, detail="Username already exists")
        if find_same_username.is_active == False:
            raise HTTPException(status_code=400, detail="Username already exists but account is deleted, try with different username")

#  to check for same email       
def find_same_email(email:str):
    find_same_email = db.query(User).filter(User.email == email).first()
    
    if find_same_email:
        if find_same_email.is_active == True:
            raise HTTPException(status_code=400, detail="email already exists")
        if find_same_email.is_active == False:
            raise HTTPException(status_code=400, detail="email already exists but account is deleted, try with different email")


# ------------------------------------------------------------


#   create a passlib context 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#   check if hash password and password entered by the user is same or not
def pass_checker(user_pass, hash_pass):
    if pwd_context.verify(user_pass, hash_pass):
        return True
    else:
        raise HTTPException(status_code=401, detail="Password is incorrect")


# --------------------------------------------------------------

# otp generation
def gen_otp(user_email, user_id):
    random_otp =  random.randint(1000, 9999)
    print("---------------------------")
    print(random_otp)
    print("===========================")

    new_otp = OTP(
        id = str(uuid.uuid4()),
        user_id = user_id,
        email = user_email,
        otp = random_otp
    )
    db.add(new_otp)
    db.commit()
    db.refresh(new_otp)
    return new_otp




# email sender
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import SENDER_EMAIL,EMAIL_PASSWORD

def send_email(receiver, subject, body):

    # SMTP Configuration (for Gmail)
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = SENDER_EMAIL
    smtp_pass = EMAIL_PASSWORD

    #build the mail system to send someone
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    #now try to send the mail to receiver 

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(SENDER_EMAIL, receiver, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")




from datetime import datetime, timedelta, timezone
import jwt
from config import SECRET_KEY, ALGORITHM
from fastapi import status, HTTPException

def get_token(id:str, username:str, email:str):
    payload = {
        "id" : id,
        "username" : username, 
        "email" : email,
        "exp" : datetime.now(timezone.utc) + timedelta(seconds=30) #expiration time
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token}

def decode_token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("id")
        email = payload.get("email")
        username = payload.get("username")
        if not id or not username or not email:
            raise HTTPException(
                tatus_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token",
            )
        return id, email, username
    except  jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
        )