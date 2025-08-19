# app/models.py
from pydantic import BaseModel, Field

# --- Modelos para la autenticación ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    nombre_usuario: str

class UserInDB(User):
    contrasena_hash: str

class UserCreate(BaseModel):
    nombre_usuario: str
    password: str = Field(min_length=6, description="La contraseña debe tener al menos 6 caracteres")

# --- Modelo de datos para los centros ---
class Centro(BaseModel):
    area: str
    especie: str | None = None
    centro: str
    tv: int | None = None
    peso: int | None = None
    sistema: str | None = None
    monitoreados: str | None = None
    fecha_apertura: str | None = None
    fecha_cierre: str | None = None
    prox_apertura: str | None = None
    ponton: str | None = None
    ex_ponton: str | None = None
    cantidad_radares: int | None = None
    nro_gps_ponton: str | None = None
    transferencias: str | None = None
    otros_datos: str | None = None