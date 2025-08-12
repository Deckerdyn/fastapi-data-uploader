import os
from datetime import datetime, timedelta
from typing import Union
import io
import csv # ¡Esta línea se ha añadido de nuevo!

import mysql.connector
import pandas as pd
import openpyxl
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

# Carga las variables de entorno del archivo .env
load_dotenv()

app = FastAPI()

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

# --- Configuración de Autenticación JWT y Hashing de Contraseñas ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key") # Usar una clave secreta fuerte y única
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # El token expirará en 30 minutos

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelos para la autenticación
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

class User(BaseModel):
    # Cambiado de nombre_centro a nombre_usuario
    nombre_usuario: str

class UserInDB(User):
    contrasena_hash: str

class UserCreate(BaseModel):
    # Cambiado de nombre_centro a nombre_usuario
    nombre_usuario: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# --- Funciones de Utilidad para Autenticación ---

def verify_password(plain_password, hashed_password):
    """Verifica si una contraseña plana coincide con su hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Genera el hash de una contraseña."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    """Crea un token de acceso JWT."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Funciones para la Base de Datos de Usuarios ---

def get_user_from_db(db_conn, username: str):
    """Obtiene un usuario de la tabla 'usuarios' por su nombre de usuario."""
    cursor = None
    try:
        cursor = db_conn.cursor(dictionary=True)
        # Cambiado de nombre_centro a nombre_usuario
        cursor.execute("SELECT nombre_usuario, contrasena_hash FROM usuarios WHERE nombre_usuario = %s", (username,))
        user_data = cursor.fetchone()
        if user_data:
            # Cambiado de nombre_centro a nombre_usuario
            return UserInDB(nombre_usuario=user_data["nombre_usuario"], contrasena_hash=user_data["contrasena_hash"])
        return None
    finally:
        if cursor:
            cursor.close()

def authenticate_user(db_conn, nombre_usuario: str, password: str):
    """Autentica un usuario verificando su contraseña."""
    user = get_user_from_db(db_conn, nombre_usuario)
    if not user:
        return None
    if not verify_password(password, user.contrasena_hash):
        return None
    return user

# --- Dependencia para Obtener el Usuario Actual (Protección de Rutas) ---

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Dependencia que decodifica el token JWT y obtiene el usuario autenticado.
    Si el token es inválido o el usuario no existe, lanza una excepción HTTPException.
    """
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

        db = get_db_connection()
        user = get_user_from_db(db, token_data.username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception
    finally:
        if db and db.is_connected():
            db.close()

# --- Modelo de datos para el formulario (existente) ---
class Centro(BaseModel):
    area: str
    especie: str
    centro: str
    peso: int | None = None
    sistema: str
    monitoreados: str
    fecha_apertura: str | None = None
    fecha_cierre: str | None = None
    prox_apertura: str | None = None
    ponton: str | None = None
    ex_ponton: str | None = None
    cantidad_radares: int | None = None
    nro_gps_ponton: str | None = None
    otros_datos: str | None = None

# Función para la conexión a la base de datos (existente)
def get_db_connection():
    """Establece una conexión con la base de datos MySQL."""
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al conectar con la base de datos: {err}")

# --- Nuevos Endpoints de Autenticación ---

@app.post("/register", response_model=User)
async def register_user(user_data: UserCreate):
    """
    Endpoint para registrar un nuevo usuario.
    Verifica si el nombre de usuario ya existe y hashea la contraseña antes de guardarla.
    """
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()

        # Verificar si el usuario ya existe (cambiado de nombre_centro a nombre_usuario)
        existing_user = get_user_from_db(db, user_data.nombre_usuario)
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de usuario ya está registrado")

        hashed_password = get_password_hash(user_data.password)
        # Cambiado de nombre_centro a nombre_usuario
        sql = "INSERT INTO usuarios (nombre_usuario, contrasena_hash) VALUES (%s, %s)"
        cursor.execute(sql, (user_data.nombre_usuario, hashed_password))
        db.commit()
        # Cambiado de nombre_centro a nombre_usuario
        return User(nombre_usuario=user_data.nombre_usuario)
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al registrar usuario en la base de datos: {err}")
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint para iniciar sesión y obtener un token de acceso JWT.
    Requiere un nombre de usuario y contraseña y devuelve un token JWT si las credenciales son válidas.
    """
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
        # El sub (subject) del token sigue siendo el nombre de usuario
        access_token = create_access_token(
            data={"sub": user.nombre_usuario}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    finally:
        if db and db.is_connected():
            db.close()


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Endpoint para obtener la información del usuario actualmente autenticado.
    Requiere un token JWT válido.
    """
    return current_user

# --- Endpoints Existentes con Autenticación Requerida ---

@app.post("/centros/")
async def create_centro(centro: Centro, current_user: User = Depends(get_current_user)):
    """
    Endpoint para recibir y guardar los datos de una sola entrada.
    Ahora requiere autenticación.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor()
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Convierte el valor de 'sistema' a mayúsculas aquí antes de la inserción
        sistema_upper = centro.sistema.upper()
        val = (
            centro.area, centro.especie, centro.centro, centro.peso, sistema_upper, centro.monitoreados,
            centro.fecha_apertura, centro.fecha_cierre, centro.prox_apertura, centro.ponton,
            centro.ex_ponton, centro.cantidad_radares, centro.nro_gps_ponton, centro.otros_datos
        )
        cursor.execute(sql, val)
        db.commit()
        return {"message": "Datos insertados correctamente"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al insertar datos: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()

@app.post("/upload-centros/")
async def upload_centros_csv(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    """
    Endpoint para recibir y procesar archivos CSV o XLSX.
    Ahora requiere autenticación.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No se ha proporcionado un archivo.")

    file_extension = os.path.splitext(file.filename)[1].lower()

    if file_extension not in ['.csv', '.xlsx']:
        raise HTTPException(status_code=400, detail="El archivo debe ser de tipo .csv o .xlsx")

    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        nombre_reporte = os.path.splitext(file.filename)[0]

        # Paso 1: Leer el archivo y convertir a CSV si es Excel
        if file_extension == '.xlsx':
            try:
                # Leer el archivo de Excel y encontrar el encabezado dinámicamente
                file_bytes = await file.read()
                file_stream = io.BytesIO(file_bytes)
                
                df_temp = pd.read_excel(file_stream, sheet_name="Todos los centros", header=None)
                
                header_row_index = -1
                for i, row in df_temp.iterrows():
                    if 'Centro' in row.values:
                        header_row_index = i
                        break
                
                if header_row_index == -1:
                    raise HTTPException(status_code=400, detail="No se pudo encontrar la fila de encabezado 'Centro' en el archivo.")
                
                # Volver a leer el archivo, esta vez usando la fila de encabezado correcta
                file_stream.seek(0)
                df = pd.read_excel(file_stream, sheet_name="Todos los centros", header=header_row_index)

                # Limpiar los nombres de las columnas: eliminar espacios, puntos, etc., y convertirlos a minúsculas
                df.columns = df.columns.astype(str).str.strip().str.replace('.', '', regex=False).str.replace(' ', '_', regex=False).str.lower()
                
                # Eliminar columnas con nombres nulos o vacíos
                df = df.loc[:, df.columns.notna()]
                df = df.loc[:, df.columns != '']
                
                # Eliminar filas donde todos los valores son nulos
                df.dropna(how='all', inplace=True)

                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=False, sep=';', encoding='utf-8')
                csv_buffer.seek(0)
                csv_reader = csv.DictReader(csv_buffer, delimiter=';')
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Error al leer el archivo de Excel: {e}")
        else: # Si es CSV
            contents = await file.read()
            csv_file = io.StringIO(contents.decode('utf-8-sig', errors='ignore'))
            csv_reader = csv.DictReader(csv_file, delimiter=';') 

        # Paso 2: Insertar reporte en la base de datos
        sql_insert_reporte = "INSERT INTO `reportes` (`fecha_subida`, `nombre_reporte`) VALUES (NOW(), %s)"
        cursor.execute(sql_insert_reporte, (nombre_reporte,))
        db.commit()
        id_reporte = cursor.lastrowid
        
        insert_count = 0
        skip_count = 0 
        
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`, `id_reporte`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        for row in csv_reader:
            try:
                # Usamos .get() para evitar errores si la columna no existe
                centro_nombre = row.get('centro') # Columna limpia
                if not centro_nombre or not str(centro_nombre).strip():
                    print("Error: Se encontró una fila sin nombre de centro. Se omite.")
                    continue
                
                # --- NUEVA COMPROBACIÓN: Si el valor es el nombre de la columna, omite la fila
                if centro_nombre.strip().lower() == 'centro':
                    print(f"Advertencia: Se omitió la fila de encabezado: {row}")
                    skip_count += 1
                    continue
                # --------------------------

                check_sql = "SELECT centro FROM centros WHERE centro = %s AND `id_reporte` = %s"
                cursor.execute(check_sql, (centro_nombre, id_reporte))
                existing_centro = cursor.fetchone()

                if existing_centro:
                    print(f"Advertencia: El centro '{centro_nombre}' ya existe para el reporte {id_reporte}. Se omite la inserción.")
                    skip_count += 1
                    continue
                
                # Convierte el valor de 'sistema' a mayúsculas aquí antes de la inserción
                sistema_from_file = row.get('sistema')
                sistema_upper_from_file = sistema_from_file.upper() if sistema_from_file else None

                # Convertir los valores a los tipos correctos antes de la inserción
                peso_val = row.get('peso')
                peso_val = int(peso_val) if peso_val and str(peso_val).strip().isdigit() else None
                
                cantidad_radares_val = row.get('cantidad_radares')
                cantidad_radares_val = int(cantidad_radares_val) if cantidad_radares_val and str(cantidad_radares_val).strip().isdigit() else None
                
                val = (
                    row.get('area'), row.get('especie'), row.get('centro'), 
                    peso_val,
                    sistema_upper_from_file, # Usa el valor en mayúsculas
                    row.get('monitoreados'),
                    row.get('fecha_apertura') if row.get('fecha_apertura') and row.get('fecha_apertura').strip() else None,
                    row.get('fecha_cierre') if row.get('fecha_cierre') and row.get('fecha_cierre').strip() else None,
                    row.get('prox_apertura') if row.get('prox_apertura') and row.get('prox_apertura').strip() else None,
                    row.get('pontón'),
                    row.get('ex_pontón'),
                    cantidad_radares_val,
                    row.get('nro_gps_pontón'),
                    row.get('otros_datos'),
                    id_reporte
                )
                cursor.execute(sql, val)
                insert_count += 1
            except Exception as e:
                print(f"Error al procesar la fila: {row}. Error: {e}")
                continue
                
        db.commit()
        return {"message": f"Reporte '{nombre_reporte}' (ID: {id_reporte}) creado. Se han insertado {insert_count} filas. Se han omitido {skip_count} filas duplicadas."}
        
    except mysql.connector.Error as err:
        if db and db.is_connected():
            db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al insertar datos en la base de datos: {err}")
    except Exception as e:
        if db and db.is_connected():
            db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inesperado al procesar el archivo: {e}")
    finally:
        if db and db.is_connected():
            cursor.close()
            db.close()

@app.get("/centros/")
async def get_centros(current_user: User = Depends(get_current_user)):
    """
    Endpoint para obtener todos los centros.
    Ahora requiere autenticación.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM centros")
        results = cursor.fetchall()
        # Transforma el campo 'sistema' a mayúsculas al obtener los datos
        for row in results:
            if 'sistema' in row and row['sistema'] is not None:
                row['sistema'] = row['sistema'].upper()
        return results
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al obtener datos: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()

@app.get("/reportes/")
async def get_reportes(current_user: User = Depends(get_current_user)):
    """
    Endpoint para obtener todos los IDs de reportes.
    Ahora requiere autenticación.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id_reporte, nombre_reporte, fecha_subida FROM reportes")
        results = cursor.fetchall()
        return results
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al obtener datos de reportes: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()

@app.get("/reportes/{id_reporte}")
async def get_reporte_by_id(id_reporte: int, current_user: User = Depends(get_current_user)):
    """
    Endpoint para obtener todos los centros de un reporte específico.
    Ahora requiere autenticación.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT id_reporte FROM reportes WHERE id_reporte = %s", (id_reporte,))
        reporte = cursor.fetchone()
        if not reporte:
            raise HTTPException(status_code=404, detail=f"No se encontró un reporte con el ID {id_reporte}")
            
        cursor.execute("SELECT * FROM centros WHERE id_reporte = %s", (id_reporte,))
        centros = cursor.fetchall()
        # Transforma el campo 'sistema' a mayúsculas al obtener los datos
        for row in centros:
            if 'sistema' in row and row['sistema'] is not None:
                row['sistema'] = row['sistema'].upper()
        return centros
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros del reporte: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()
