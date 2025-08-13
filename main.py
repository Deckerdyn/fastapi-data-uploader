# main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.routes import centros_router
from app.auth import auth_router

# Carga las variables de entorno del archivo .env
load_dotenv()

app = FastAPI(
    title="API de Gestión de Centros",
    description="API para gestionar centros, cargar datos y autenticación de usuarios.",
    version="1.0.0"
)

# Configuración de CORS
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://10.20.7.103:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir routers de autenticación y de centros
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Autenticación"])
app.include_router(centros_router, prefix="/api/v1/data", tags=["Gestión de Centros y Reportes"])

@app.get("/")
async def root():
    return {"message": "Bienvenido a la API de Gestión de Centros. Accede a /docs para la documentación interactiva."}