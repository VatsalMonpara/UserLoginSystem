from pydantic import BaseModel, EmailStr
from typing import Optional


class RegisterUser(BaseModel):
    username : str
    email : EmailStr
    password : str

class GetAllUser(BaseModel):
    id : str
    username: str
    email : str
    # password : str

class UpdateUser(BaseModel):
    username : Optional[str] = None
    email : Optional[EmailStr] = None
    password : Optional[str] = None


class ResetPass(BaseModel):
    old_password : str
    new_password : str
    confirm_password : str


class ForgetPass(BaseModel):
    new_password : str
    confirm_password : str