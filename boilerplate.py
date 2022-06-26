import fastapi
import jwt
import os
from hashlib import pbkdf2_hmac
from typing import Optional
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

# ORM
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from models import Users, Items, engine

# table name
tables = {'users': Users, 'items': Items}

# set up CORS
origins = [
    "http://localhost",
    "http://localhost:8080",
]

app = fastapi.FastAPI()

# add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# set up JWT
secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
algorithm = "HS256"
access_token_expire_minutes = 30

# set up templates
templates = Jinja2Templates(directory="templates")

# set up SQLAlchemy
engine = create_engine('sqlite:///./test.db')

@app.post("/login/")
def login(db: Session = Session(engine), form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Logs user in, creates access token.
    """
    user = db.query(Users).filter(Users.username == form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    hashed_password = pbkdf2_hmac(
        algorithm=hashlib.sha256,
        password=form_data.password.encode(),
        salt=user.salt.encode(),
        iterations=100000,
    )
    if hashed_password != user.hashed_password:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=timedelta(minutes=access_token_expire_minutes)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout/")
def logout(request: Request, db: Session = Session(engine)):
    """
    Logs user out, deletes access token from database.
    """
    access_token = request.headers.get("Authorization")
    if access_token is None:
        raise HTTPException(status_code=401, detail="Access token required")
    token_data = jwt.decode(access_token, str(secret_key))
    username: str = token_data.get("sub")
    user = db.query(Users).filter(Users.username == username).first()
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.access_token = None
    db.add(user)
    db.commit()
    return {"message": "Successfully logged out"}


@app.post("/token/refresh/", response_model=schemas.Token)
def refresh_access_token(request: Request, db: Session = Session(engine)):
    """
    Refreshes access token.
    """
    access_token = request.headers.get("Authorization")
    if access_token is None:
        raise HTTPException(status_code=401, detail="Access token required")
    token_data = jwt.decode(access_token, str(secret_key))
    username: str = token_data.get("sub")
    user = db.query(Users).filter(Users.username == username).first()
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    if user.access_token_expiration and user.access_token_expiration < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Token expired")

    access_token_expires = timedelta(minutes=access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    user.access_token = access_token
    user.access_token_expiration = datetime.utcnow() + access_token_expires
    db.add(user)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}

# set up endpoints
@app.get("/")
def read_root():
    return {"message": "Hello, world!"}


@app.get("/items/{id}")
def read_item(id: int, q: Optional[str] = None):
    return {"item_id": id, "q": q}


@app.post("/items/")
def create_item(item: Item):
    return item

@app.get("/docs")
def read_docs():
    """
    Returns documentation for all other endpoints.
    """
    # retrieve documentation for all other endpoints
    endpoints = [
        {"url": "/", "methods": ["GET"], "params": []},
        {"url": "/items/{id}", "methods": ["GET"], "params": ["id"]},
        {"url": "/items/", "methods": ["POST"], "params": ["item"]},
    ]
    return {"endpoints": endpoints}
