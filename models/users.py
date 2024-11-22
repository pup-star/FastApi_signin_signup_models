from typing import Generic, Optional, TypeVar
from pydantic.generics import GenericModel
from pydantic import BaseModel, Field

T = TypeVar('T')

# Login ----------
class Login(BaseModel):
    username: str
    password: str

# Register ----------
class Register(BaseModel):
    username: str
    email: str
    phone_number: str
    password: str
    password: str
    first_name: str
    last_name: str

# response model
class ResponseSchema(BaseModel):
    code: str
    status: str
    message: str
    result: Optional[T] = None

# token
class TokenResponse(BaseModel):
    access_token :str
    token_type: str