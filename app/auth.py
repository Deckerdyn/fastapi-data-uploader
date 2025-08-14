# app/auth.py
import os
from datetime import datetime, timedelta, timezone

import mysql.connector
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

from app.database import get_db_connection
from app.models import Token, TokenData, User, UserInDB, UserCreate

# Carga las variables de entorno del archivo .env
load_dotenv()

auth_router = APIRouter()

# --- Configuración de Autenticación con JWT ---
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("La variable de entorno SECRET_KEY no está configurada.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 720

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_db(db_conn, username: str):
    cursor = None
    try:
        cursor = db_conn.cursor(dictionary=True)
        cursor.execute("SELECT nombre_usuario, contrasena_hash FROM usuarios WHERE nombre_usuario = %s", (username,))
        user_data = cursor.fetchone()
        if user_data:
            return UserInDB(nombre_usuario=user_data["nombre_usuario"], contrasena_hash=user_data["contrasena_hash"])
        return None
    finally:
        if cursor:
            cursor.close()

def authenticate_user(db_conn, nombre_usuario: str, password: str):
    user = get_user_from_db(db_conn, nombre_usuario)
    if not user:
        return None
    if not verify_password(password, user.contrasena_hash):
        return None
    return user

async def get_current_user_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    db = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    try:
        db = get_db_connection()
        user = get_user_from_db(db, username=token_data.username)
        if user is None:
            raise credentials_exception
        return user
    finally:
        if db and db.is_connected():
            db.close()

@auth_router.post("/register", response_model=User)
async def register_user(user_data: UserCreate):
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        existing_user = get_user_from_db(db, user_data.nombre_usuario)
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de usuario ya está registrado")
        hashed_password = get_password_hash(user_data.password)
        sql = "INSERT INTO usuarios (nombre_usuario, contrasena_hash) VALUES (%s, %s)"
        cursor.execute(sql, (user_data.nombre_usuario, hashed_password))
        db.commit()
        return User(nombre_usuario=user_data.nombre_usuario)
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al registrar usuario en la base de datos: {err}")
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

@auth_router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = None
    try:
        db = get_db_connection()
        user = authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nombre de usuario o contraseña incorrectos",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.nombre_usuario}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    finally:
        if db and db.is_connected():
            db.close()