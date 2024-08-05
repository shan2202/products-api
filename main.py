import os
from typing import Annotated, Union
from fastapi import Depends, FastAPI, Header, HTTPException, status, Form, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ValidationError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy import Boolean, Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from fastapi.encoders import jsonable_encoder
import os

# to get a string like this run:
# openssl rand -hex 32
# get from env
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
# SECRET_KEY = os.environ.get('JWT_SECRET')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database configurations
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# SQLAlchemy models
class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String, index=True)


class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    fullname = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=True)
    admin = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)

fake_users_db = {}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None
    admin: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    db = SessionLocal()
    user = db.query(Users).filter(Users.username == username).first()
    print(user.username)
    if user:
        return UserInDB(**jsonable_encoder(user))


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    db = SessionLocal()
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_admin_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if not current_user.admin:
        raise HTTPException(status_code=401, detail="Not Authorized for Non-admin user")
    return current_user


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/products", dependencies=[Depends(get_current_active_user), Depends(get_admin_user)])
async def create_item(name: str, description: str, response: Response):
    db = SessionLocal()
    db_item = Item(name=name, description=description)
    item_name = db.query(Item).filter(Item.name == name).first()
    if item_name:
        raise HTTPException(status_code=422, detail="Item name should be unique")
    else:
        db.add(db_item)
        db.commit()
        db.refresh(db_item)
        response.status_code= status.HTTP_201_CREATED
        return response


# Read (GET)
@app.get("/products/{product_id}", dependencies=[Depends(get_current_active_user)])
async def read_item(product_id: int):
    db = SessionLocal()
    item = db.query(Item).filter(Item.id == product_id).first()
    if item:
        return item
    else:
        raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products", dependencies=[Depends(get_current_active_user)])
async def read_item():
    db = SessionLocal()
    item = db.query(Item).offset(0).limit(100).all()
    if item:
        return item
    else:
        # return {"message": "No items found"}
        raise HTTPException(status_code=204, detail="No Products available")


# Update (PUT)
@app.put("/products/{product_id}", dependencies=[Depends(get_current_active_user), Depends(get_admin_user)])
async def update_item(item_id: int, name: str, description: str):
    db = SessionLocal()
    db_item = db.query(Item).filter(Item.id == item_id).first()
    db_item.name = name
    db_item.description = description
    db.commit()
    return db_item


# Delete (DELETE)
@app.delete("/products/{product_id}", dependencies=[Depends(get_current_active_user), Depends(get_admin_user)])
async def delete_item(item_id: int):
    db = SessionLocal()
    db_item = db.query(Item).filter(Item.id == item_id).first()
    db.delete(db_item)
    db.commit()
    return {"message": "Product deleted successfully"}


#
#
@app.post("/createUser/", dependencies=[Depends(get_current_active_user), Depends(get_admin_user)])
async def create_user(username: str, fullname: str, email: str, password: str):
    db = SessionLocal()
    hashed_password = get_password_hash(password)
    db_user = Users(username=username, fullname=fullname, email=email, hashed_password=hashed_password,
                    disabled=False, admin=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
