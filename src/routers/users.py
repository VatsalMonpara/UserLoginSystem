from fastapi import APIRouter, HTTPException
from database.database import Sessionlocal
from src.models.users import User, OTP
from src.schemas.users import RegisterUser, GetAllUser, UpdateUser, ResetPass, ForgetPass
from src.utils.users import pwd_context, find_same_email, find_same_username, send_email, pass_checker, get_token, gen_otp
from logs.log_config import logger
import uuid


user_router = APIRouter()
db = Sessionlocal()


#-------------------- ~ REGISTER USER ~ --------------------#

@user_router.post("/register_user")
def register_user(user:RegisterUser):
    new_user = User(
        id = str(uuid.uuid4()),
        username = user.username,
        email = user.email,
        password = pwd_context.hash(user.password)
    )

    find_one_entry = db.query(User).first()
    if find_one_entry :        
        find_same_username(user.username)        
        find_same_email(user.email) 

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info(f"User {new_user.username} registered successfully")
    return "User registration successfull, you can proceed for verification"



#-------------------- ~ GENERATE OTP ~ --------------------#

@user_router.post("/generate_otp")
def generate_otp(email:str):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == False, User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")

    random_otp = gen_otp(find_user.email, find_user.id)
    
    send_email(find_user.email, "Test Email", f"Otp is {random_otp}")

   
    logger.info("Otp generated successfully for verification")
    return "Otp has been generated successfully"



#-------------------- ~ VERIFICATION USING OTP ~ --------------------#

@user_router.get("/verify_otp}")
def verify_otp(email:str, otp:str):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_deleted == False, User.is_verified == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    find_otp = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
    if not find_otp:
        raise HTTPException(status_code=400, detail="Otp is not correct")
        
    
    find_user.is_verified = True
    logger.info(f"User {find_user.username} verified")
    db.delete(find_otp)
    db.commit()
    db.refresh(find_user)
    return "Otp verified successfully"  



#-------------------- ~ GET ALL USER ~ --------------------#

@user_router.get("/get_all_user", response_model=list[GetAllUser])
def get_all_user():
    all_user = db.query(User).filter(User.is_active == True, User.is_deleted == False, User.is_verified == True).all()

    if not all_user:
        raise HTTPException(status_code=400, detail="No users found")
    return all_user


#-------------------- ~ GET SINGLE USER ~ --------------------#

@user_router.get("/get_user/{user_id}", response_model=GetAllUser)
def get_user(user_id:str):
    find_user = db.query(User).filter(User.id == user_id, User.is_active == True, User.is_deleted == False, User.is_verified == True).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    return find_user



#-------------------- ~ UPDATE USER PARTIALLY ~ --------------------#

@user_router.patch("/update_user/{user_id}")
def update_user(user_id:str, user:UpdateUser):
    find_user = db.query(User).filter(User.id == user_id, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")

    new_user_schema_without_none = user.model_dump(exclude_none=True)

    for key, value in new_user_schema_without_none.items():
        if key == "password":
            setattr(find_user, key, pwd_context.hash(value))
        else:
            find_same_email(value)
            find_same_username(value)
            setattr(find_user, key, value)
    
    db.commit()
    db.refresh(find_user)
    logger.info(f"User {find_user.username} was updated")
    return {"message": "user update successfully", "data":find_user}




#-------------------- ~ LOGIN USER ~ --------------------#

@user_router.get("/login_user")
def login_user(email:str, password:str):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_deleted == False, User.is_verified == True).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    pass_checker(password, find_user.password)

    access_token = get_token(find_user.id, find_user.username, find_user.email)
    logger.info(f"User {find_user.username} logged in successfully")
    return access_token



#-------------------- ~ DELETE USER ~ --------------------#

@user_router.delete("/delete_user/{user_id}")
def delete_user(user_id:str):
    find_user = db.query(User).filter(User.id == user_id, User.is_active == True, User.is_verified == True).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    if find_user.is_deleted == True:
        raise HTTPException(status_code=400, detail="User already deleted")
    
    find_user.is_deleted = True
    find_user.is_active = False
    find_user.is_verified = False
    db.commit()
    db.refresh(find_user)
    logger.info(f"User {find_user.username} was deleted")

    return {"message":"User successfully deleted", "data":find_user}



#-------------------- ~ RESET PASSWORD ~ --------------------#

@user_router.patch("/reset_password")
def reset_pass(email:str, user: ResetPass):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    pass_checker(user.old_password, find_user.password)

    if user.new_password == user.confirm_password:
        setattr(find_user , "password", pwd_context.hash(user.confirm_password))
    else:
        raise HTTPException(status_code=400, detail="Password confirmation does not match new password")
    
    db.commit()
    db.refresh(find_user)
    logger.info(f"User {find_user.username} reseted their password")
    return "Password changed successfully, you can login again"



#-------------------- ~ OTP FOR FORGOT PASSWORD ~ --------------------#
@user_router.post("/generate_otp_pass")
def generate_otp_pass(email:str):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")

    
    random_otp = gen_otp(find_user.email, find_user.id)
    send_email(find_user.email, "otp", f"Otp for new password generation is {random_otp}")

    logger.info("Otp generated successfully for changing password")
    return "Otp has been generated successfully"



#-------------------- ~ FORGOT PASSWORD ~ --------------------#

@user_router.patch("/forgot_password")
def forgot_pass(email:str, otp:str, user: ForgetPass):
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    find_otp = db.query(OTP).filter(OTP.otp == otp, OTP.email == email).first()
    if not find_otp:
        raise HTTPException(status_code=400, detail="OTP not found")
    
    if user.new_password == user.confirm_password:
        setattr(find_user , "password", pwd_context.hash(user.confirm_password))
    else:
        raise HTTPException(status_code=400, detail="Password confirmation does not match new password")
    
    db.delete(find_otp)
    db.commit()
    db.refresh(find_user)
    logger.info(f"User {find_user.username} changed their password")
    return "Password changed successfully, you can login again"