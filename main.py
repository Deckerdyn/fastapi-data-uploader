import os
import io
import csv

import mysql.connector
import pandas as pd
import openpyxl
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
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

# --- Configuración de Autenticación Básica y Hashing de Contraseñas ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
basic_auth_scheme = HTTPBasic()

# Modelos para la autenticación
class User(BaseModel):
    nombre_usuario: str

class UserInDB(User):
    contrasena_hash: str

class UserCreate(BaseModel):
    nombre_usuario: str
    password: str

# --- Funciones de Utilidad para Autenticación ---

def verify_password(plain_password, hashed_password):
    """Verifica si una contraseña plana coincide con su hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Genera el hash de una contraseña."""
    return pwd_context.hash(password)

# --- Funciones para la Base de Datos de Usuarios ---

def get_user_from_db(db_conn, username: str):
    """Obtiene un usuario de la tabla 'usuarios' por su nombre de usuario."""
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
    """Autentica un usuario verificando su contraseña."""
    user = get_user_from_db(db_conn, nombre_usuario)
    if not user:
        return None
    if not verify_password(password, user.contrasena_hash):
        return None
    return user

# --- Dependencia para Obtener el Usuario Actual (Protección de Rutas) ---
# Esta dependencia solo se usará en los endpoints que queremos proteger.
async def get_current_user(credentials: HTTPBasicCredentials = Depends(basic_auth_scheme)):
    """
    Dependencia que valida las credenciales de autenticación básica y obtiene el usuario autenticado.
    Si las credenciales no son válidas o el usuario no existe, lanza una excepción HTTPException.
    """
    db = None
    try:
        db = get_db_connection()
        user = authenticate_user(db, credentials.username, credentials.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales de autenticación inválidas",
                headers={"WWW-Authenticate": "Basic"}, # Indica al cliente que use autenticación básica
            )
        return user
    finally:
        if db and db.is_connected():
            db.close()

# --- Modelo de datos para el formulario (existente) ---
class Centro(BaseModel):
    area: str
    especie: str | None = None
    centro: str
    peso: int | None = None
    sistema: str | None = None
    # Modificación: monitoreados ahora es opcional y puede ser None
    monitoreados: str | None = None 
    fecha_apertura: str | None = None
    fecha_cierre: str | None = None
    prox_apertura: str | None = None
    # Modificación: ponton ahora es opcional y puede ser None
    ponton: str | None = None
    # Modificación: ex_ponton ahora es opcional y puede ser None
    ex_ponton: str | None = None
    cantidad_radares: int | None = None
    # Modificación: nro_gps_ponton ahora es opcional y puede ser None
    nro_gps_ponton: str | None = None
    # Modificación: otros_datos ahora es opcional y puede ser None
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

# --- Endpoints de Autenticación Básica (Protegidos) ---

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

@app.post("/login", response_model=User)
async def login(current_user: User = Depends(get_current_user)):
    """
    Endpoint para que el usuario inicie sesión con autenticación básica.
    Si las credenciales son válidas, devuelve la información del usuario autenticado.
    Este endpoint sirve para verificar las credenciales y confirmar el acceso.
    """
    # Si la dependencia get_current_user no lanza una excepción, las credenciales son válidas.
    # Simplemente devolvemos la información del usuario.
    return current_user

# --- Endpoints de Gestión de Datos (AHORA PÚBLICOS - NO REQUIEREN AUTENTICACIÓN) ---

@app.post("/centros/")
async def create_centro(centro: Centro): # Eliminado: , current_user: User = Depends(get_current_user)
    """
    Endpoint para recibir y guardar los datos de una sola entrada.
    YA NO REQUIERE AUTENTICACIÓN.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor()
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Asegúrate de que sistema_upper_val sea None si centro.sistema es None o una cadena vacía
        sistema_upper_val = centro.sistema.upper() if centro.sistema and centro.sistema.strip() else None
        
        val = (
            centro.area, 
            # Asegúrate de que especie_val sea None si centro.especie es None o una cadena vacía
            centro.especie if centro.especie and centro.especie.strip() else None, 
            centro.centro, 
            centro.peso, 
            sistema_upper_val, 
            # Modificación: monitoreados_val ahora es None si la cadena está vacía o es None
            centro.monitoreados if centro.monitoreados and centro.monitoreados.strip() else None,
            centro.fecha_apertura, 
            centro.fecha_cierre, 
            centro.prox_apertura, 
            # Modificación: ponton_val ahora es None si la cadena está vacía o es None
            centro.ponton if centro.ponton and centro.ponton.strip() else None,
            # Modificación: ex_ponton_val ahora es None si la cadena está vacía o es None
            centro.ex_ponton if centro.ex_ponton and centro.ex_ponton.strip() else None,
            centro.cantidad_radares, 
            # Modificación: nro_gps_ponton_val ahora es None si la cadena está vacía o es None
            centro.nro_gps_ponton if centro.nro_gps_ponton and centro.nro_gps_ponton.strip() else None,
            # Modificación: otros_datos_val ahora es None si la cadena está vacía o es None
            centro.otros_datos if centro.otros_datos and centro.otros_datos.strip() else None
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
async def upload_centros_csv(file: UploadFile = File(...)): # Eliminado: , current_user: User = Depends(get_current_user)
    """
    Endpoint para recibir y procesar archivos CSV o XLSX.
    YA NO REQUIERE AUTENTICACIÓN.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No se ha proporcionado un archivo.")

    file_extension = os.path.splitext(file.filename)[1].lower()

    if file_extension not in ['.csv', '.xlsx']:
        raise HTTPException(status_code=400, detail="El archivo debe ser de tipo .csv o .xlsx")

    db = None
    cursor = None
    nombre_reporte = os.path.splitext(file.filename)[0]
    id_reporte = None # Inicializar id_reporte a None

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        if file_extension == '.xlsx':
            try:
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
                
                file_stream.seek(0)
                df = pd.read_excel(file_stream, sheet_name="Todos los centros", header=header_row_index)

                df.columns = df.columns.astype(str).str.strip().str.replace('.', '', regex=False).str.replace(' ', '_', regex=False).str.lower()
                
                df = df.loc[:, df.columns.notna()]
                df = df.loc[:, df.columns != '']
                
                df.dropna(how='all', inplace=True)

                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=False, sep=';', encoding='utf-8')
                csv_buffer.seek(0)
                csv_reader = csv.DictReader(csv_buffer, delimiter=';')
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Error al leer el archivo de Excel: {e}")
        else:
            contents = await file.read()
            csv_file = io.StringIO(contents.decode('utf-8-sig', errors='ignore'))
            csv_reader = csv.DictReader(csv_file, delimiter=';') 

        insert_count = 0
        skip_count = 0 
        
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`, `id_reporte`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        rows_to_insert = [] # Lista para almacenar los datos a insertar en un solo batch
        
        for row in csv_reader:
            try:
                centro_nombre = row.get('centro')
                if not centro_nombre or not str(centro_nombre).strip():
                    print("Error: Se encontró una fila sin nombre de centro. Se omite.")
                    skip_count += 1
                    continue
                
                if centro_nombre.strip().lower() == 'centro':
                    print(f"Advertencia: Se omitió la fila de encabezado: {row}")
                    skip_count += 1
                    continue

                # Normalizar los nombres de las columnas para compatibilidad
                # Asegúrate de que las claves del diccionario sean consistentes con tu archivo
                # Aquí se asume que las claves son en minúsculas y con guiones bajos si provienen de la normalización de pandas
                sistema_from_file = row.get('sistema')
                sistema_upper_from_file = sistema_from_file.upper() if sistema_from_file and str(sistema_from_file).strip() else None

                especie_from_file = row.get('especie')
                especie_val = especie_from_file if especie_from_file and str(especie_from_file).strip() else None

                peso_val = row.get('peso')
                # Convertir a int si es un dígito, de lo contrario None
                peso_val = int(peso_val) if peso_val and str(peso_val).strip().isdigit() else None
                
                cantidad_radares_val = row.get('cantidad_radares')
                cantidad_radares_val = int(cantidad_radares_val) if cantidad_radares_val and str(cantidad_radares_val).strip().isdigit() else None
                
                monitoreados_val = row.get('monitoreados')
                monitoreados_val = monitoreados_val if monitoreados_val and str(monitoreados_val).strip() else None

                ponton_val = row.get('pontón') if row.get('pontón') else row.get('ponton') # Considera ambas claves
                ponton_val = ponton_val if ponton_val and str(ponton_val).strip() else None

                ex_ponton_val = row.get('ex_pontón') if row.get('ex_pontón') else row.get('ex_ponton') # Considera ambas claves
                ex_ponton_val = ex_ponton_val if ex_ponton_val and str(ex_ponton_val).strip() else None

                nro_gps_ponton_val = row.get('nro_gps_pontón') if row.get('nro_gps_pontón') else row.get('nro_gps_ponton') # Considera ambas claves
                nro_gps_ponton_val = nro_gps_ponton_val if nro_gps_ponton_val and str(nro_gps_ponton_val).strip() else None

                otros_datos_val = row.get('otros_datos')
                otros_datos_val = otros_datos_val if otros_datos_val and str(otros_datos_val).strip() else None

                rows_to_insert.append((
                    row.get('area'), 
                    especie_val, 
                    centro_nombre, # Usar la variable centro_nombre ya validada
                    peso_val,
                    sistema_upper_from_file,
                    monitoreados_val,
                    row.get('fecha_apertura') if row.get('fecha_apertura') and str(row.get('fecha_apertura')).strip() else None,
                    row.get('fecha_cierre') if row.get('fecha_cierre') and str(row.get('fecha_cierre')).strip() else None,
                    row.get('prox_apertura') if row.get('prox_apertura') and str(row.get('prox_apertura')).strip() else None,
                    ponton_val,
                    ex_ponton_val,
                    cantidad_radares_val,
                    nro_gps_ponton_val,
                    otros_datos_val,
                    # id_reporte se agregará más tarde si hay inserciones exitosas
                ))
            except Exception as e:
                print(f"Error al preparar la fila para la inserción: {row}. Error: {e}")
                skip_count += 1
                continue
        
        # Verificar si hay filas válidas para insertar
        if not rows_to_insert:
            raise HTTPException(status_code=400, detail=f"No se encontraron filas válidas para insertar en el archivo. Se han omitido {skip_count} filas.")

        # Insertar el reporte solo si hay filas válidas de centros
        sql_insert_reporte = "INSERT INTO `reportes` (`fecha_subida`, `nombre_reporte`) VALUES (NOW(), %s)"
        cursor.execute(sql_insert_reporte, (nombre_reporte,))
        db.commit() # Confirmar la inserción del reporte para obtener su ID
        id_reporte = cursor.lastrowid

        # Insertar las filas de centros con el id_reporte obtenido
        final_insert_values = []
        for row_data in rows_to_insert:
            # Antes de agregar a final_insert_values, verifica la existencia del centro
            centro_existente_check_sql = "SELECT centro FROM centros WHERE centro = %s AND `id_reporte` = %s"
            cursor.execute(centro_existente_check_sql, (row_data[2], id_reporte)) # row_data[2] es el nombre del centro
            existing_centro = cursor.fetchone()

            if existing_centro:
                print(f"Advertencia: El centro '{row_data[2]}' ya existe para el reporte {id_reporte}. Se omite la inserción.")
                skip_count += 1
                continue
            
            final_insert_values.append(row_data + (id_reporte,)) # Agregar id_reporte a cada tupla

        if not final_insert_values:
            # Si después de las validaciones y chequeos de duplicados no hay nada para insertar,
            # revertir la creación del reporte
            db.rollback()
            raise HTTPException(status_code=400, detail=f"No se insertó ninguna fila de centros. El reporte '{nombre_reporte}' no fue registrado. Se han omitido {skip_count} filas.")

        cursor.executemany(sql, final_insert_values)
        insert_count = cursor.rowcount # Obtener el número de filas insertadas
        db.commit() # Confirmar las inserciones de centros

        return {"message": f"Reporte '{nombre_reporte}' (ID: {id_reporte}) creado. Se han insertado {insert_count} filas. Se han omitido {skip_count} filas duplicadas o inválidas."}
        
    except mysql.connector.Error as err:
        if db and db.is_connected():
            db.rollback() # Asegurar que se revierta si hay un error en la BD
        raise HTTPException(status_code=500, detail=f"Error al insertar datos en la base de datos: {err}")
    except HTTPException as http_exc:
        if db and db.is_connected() and id_reporte:
            # Si se creó el reporte pero no se insertaron centros, se revierte el reporte
            db.rollback() 
        raise http_exc # Re-lanzar la excepción HTTP
    except Exception as e:
        if db and db.is_connected():
            db.rollback() # Asegurar que se revierta si hay un error inesperado
        raise HTTPException(status_code=500, detail=f"Error inesperado al procesar el archivo: {e}")
    finally:
        if db and db.is_connected():
            cursor.close()
            db.close()

@app.get("/centros/")
async def get_centros(): # Eliminado: current_user: User = Depends(get_current_user)
    """
    Endpoint para obtener todos los centros.
    YA NO REQUIERE AUTENTICACIÓN.
    """
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM centros")
        results = cursor.fetchall()
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
async def get_reportes(): # Eliminado: current_user: User = Depends(get_current_user)
    """
    Endpoint para obtener todos los IDs de reportes.
    YA NO REQUIERE AUTENTICACIÓN.
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
async def get_reporte_by_id(id_reporte: int): # Eliminado: , current_user: User = Depends(get_current_user)
    """
    Endpoint para obtener todos los centros de un reporte específico.
    YA NO REQUIERE AUTENTICACIÓN.
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
