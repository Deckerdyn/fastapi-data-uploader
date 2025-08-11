# main.py
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import mysql.connector
import csv
import io
import os
from dotenv import load_dotenv
import pandas as pd
import openpyxl
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from typing import Annotated
from datetime import datetime, timedelta

# Carga las variables de entorno del archivo .env
load_dotenv()

app = FastAPI()

# Configuración para el hasheo de contraseñas
contexto_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Clave secreta para JWT
#SECRET_KEY = os.getenv("SECRET_KEY", "123")
ALGORITMO = "HS256"
TIEMPO_EXPIRACION_TOKEN_MINUTOS = 30

# Esquema de autenticación OAuth2
esquema_oauth2 = OAuth2PasswordBearer(tokenUrl="/token")

# --- Modelos de datos de autenticación ---
class CredencialesUsuario(BaseModel):
    nombre_usuario: str
    contrasena: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Funciones de la base de datos y seguridad ---
def obtener_conexion_db():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al conectar con la base de datos: {err}")

def hashear_contrasena(contrasena: str):
    return contexto_pwd.hash(contrasena)

def verificar_contrasena(contrasena_plana: str, contrasena_hash: str):
    return contexto_pwd.verify(contrasena_plana, contrasena_hash)

def buscar_usuario_en_db(nombre_usuario: str):
    try:
        db = obtener_conexion_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE nombre_usuario = %s", (nombre_usuario,))
        usuario = cursor.fetchone()
        return usuario
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()

def crear_token_acceso(datos: dict, tiempo_expiracion: timedelta | None = None):
    a_codificar = datos.copy()
    if tiempo_expiracion:
        expirar = datetime.utcnow() + tiempo_expiracion
    else:
        expirar = datetime.utcnow() + timedelta(minutes=TIEMPO_EXPIRACION_TOKEN_MINUTOS)
    a_codificar.update({"exp": expirar})
    token_codificado = jwt.encode(a_codificar, SECRET_KEY, algorithm=ALGORITMO)
    return token_codificado

async def obtener_usuario_actual(token: Annotated[str, Depends(esquema_oauth2)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITMO])
        nombre_usuario: str = payload.get("sub")
        if nombre_usuario is None:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        usuario = buscar_usuario_en_db(nombre_usuario)
        if usuario is None:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        return usuario
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# --- Endpoints de autenticación ---
@app.post("/register/")
def register_user(usuario_data: CredencialesUsuario):
    if buscar_usuario_en_db(usuario_data.nombre_usuario):
        raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
    
    contrasena_hasheada = hashear_contrasena(usuario_data.contrasena)
    try:
        db = obtener_conexion_db()
        cursor = db.cursor()
        sql = "INSERT INTO usuarios (nombre_usuario, contrasena_hash) VALUES (%s, %s)"
        val = (usuario_data.nombre_usuario, contrasena_hasheada)
        cursor.execute(sql, val)
        db.commit()
        return {"message": "Usuario creado exitosamente"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al registrar usuario: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()

@app.post("/token", response_model=Token)
async def login_for_access_token(formulario_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    usuario = buscar_usuario_en_db(formulario_data.username)
    if not usuario or not verificar_contrasena(formulario_data.password, usuario['contrasena_hash']):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    
    tiempo_expiracion = timedelta(minutes=TIEMPO_EXPIRACION_TOKEN_MINUTOS)
    token_acceso = crear_token_acceso(
        datos={"sub": usuario['nombre_usuario']}, tiempo_expiracion=tiempo_expiracion
    )
    return {"access_token": token_acceso, "token_type": "bearer"}

# Configuración de CORS
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://10.20.7.103:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de datos para el formulario
class Centro(BaseModel):
    area: str
    especie: str | None = None  # Se permite que sea None
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

# Función para la conexión a la base de datos
def get_db_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al conectar con la base de datos: {err}")

# Endpoint para recibir y guardar los datos de una sola entrada
@app.post("/centros/")
async def create_centro(centro: Centro):
    try:
        db = get_db_connection()
        cursor = db.cursor()
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Convierte el valor de 'sistema' a mayúsculas aquí antes de la inserción
        sistema_upper = centro.sistema.upper()
        
        # Convierte el valor de 'especie' a None si es una cadena vacía o solo espacios
        especie_val = centro.especie.strip() if centro.especie else None
        especie_val = especie_val if especie_val != "" else None

        # Convierte los valores de campos opcionales a None si son cadenas vacías o solo espacios
        fecha_apertura_val = centro.fecha_apertura.strip() if centro.fecha_apertura else None
        fecha_apertura_val = fecha_apertura_val if fecha_apertura_val != "" else None

        fecha_cierre_val = centro.fecha_cierre.strip() if centro.fecha_cierre else None
        fecha_cierre_val = fecha_cierre_val if fecha_cierre_val != "" else None

        prox_apertura_val = centro.prox_apertura.strip() if centro.prox_apertura else None
        prox_apertura_val = prox_apertura_val if prox_apertura_val != "" else None

        ponton_val = centro.ponton.strip() if centro.ponton else None
        ponton_val = ponton_val if ponton_val != "" else None

        ex_ponton_val = centro.ex_ponton.strip() if centro.ex_ponton else None
        ex_ponton_val = ex_ponton_val if ex_ponton_val != "" else None

        nro_gps_ponton_val = centro.nro_gps_ponton.strip() if centro.nro_gps_ponton else None
        nro_gps_ponton_val = nro_gps_ponton_val if nro_gps_ponton_val != "" else None

        otros_datos_val = centro.otros_datos.strip() if centro.otros_datos else None
        otros_datos_val = otros_datos_val if otros_datos_val != "" else None


        val = (
            centro.area, especie_val, centro.centro, centro.peso, sistema_upper, centro.monitoreados,
            fecha_apertura_val, fecha_cierre_val, prox_apertura_val, ponton_val,
            ex_ponton_val, centro.cantidad_radares, nro_gps_ponton_val, otros_datos_val
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

# Endpoint para recibir y procesar archivos CSV o XLSX
@app.post("/upload-centros/")
async def upload_centros_csv(file: UploadFile = File(...)):
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
        
        processed_rows = [] # Lista para almacenar filas válidas antes de insertar

        # Paso 1: Leer el archivo y convertir a CSV si es Excel
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
        else: # Si es CSV
            contents = await file.read()
            csv_file = io.StringIO(contents.decode('utf-8-sig', errors='ignore'))
            csv_reader = csv.DictReader(csv_file, delimiter=';') 

        # --- PRE-PROCESAMIENTO: Recolectar filas válidas ---
        skip_count = 0 
        
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
                
                # Pre-validaciones y transformación de tipos para cada fila
                sistema_from_file = row.get('sistema')
                sistema_upper_from_file = sistema_from_file.upper() if sistema_from_file else None

                especie_from_file = row.get('especie')
                especie_val_from_file = especie_from_file.strip() if especie_from_file else None
                especie_val_from_file = especie_val_from_file if especie_val_from_file != "" else None

                fecha_apertura_from_file = row.get('fecha_apertura')
                fecha_apertura_val_from_file = fecha_apertura_from_file.strip() if fecha_apertura_from_file else None
                fecha_apertura_val_from_file = fecha_apertura_val_from_file if fecha_apertura_val_from_file != "" else None

                fecha_cierre_from_file = row.get('fecha_cierre')
                fecha_cierre_val_from_file = fecha_cierre_from_file.strip() if fecha_cierre_from_file else None
                fecha_cierre_val_from_file = fecha_cierre_val_from_file if fecha_cierre_val_from_file != "" else None

                prox_apertura_from_file = row.get('prox_apertura')
                prox_apertura_val_from_file = prox_apertura_from_file.strip() if prox_apertura_from_file else None
                prox_apertura_val_from_file = prox_apertura_val_from_file if prox_apertura_val_from_file != "" else None

                ponton_from_file = row.get('ponton')
                ponton_val_from_file = ponton_from_file.strip() if ponton_from_file else None
                ponton_val_from_file = ponton_val_from_file if ponton_val_from_file != "" else None

                ex_ponton_from_file = row.get('ex_ponton')
                ex_ponton_val_from_file = ex_ponton_from_file.strip() if ex_ponton_from_file else None
                ex_ponton_val_from_file = ex_ponton_val_from_file if ex_ponton_val_from_file != "" else None

                nro_gps_ponton_from_file = row.get('nro_gps_ponton')
                nro_gps_ponton_val_from_file = nro_gps_ponton_from_file.strip() if nro_gps_ponton_from_file else None
                nro_gps_ponton_val_from_file = nro_gps_ponton_val_from_file if nro_gps_ponton_val_from_file != "" else None

                otros_datos_from_file = row.get('otros_datos')
                otros_datos_val_from_file = otros_datos_from_file.strip() if otros_datos_from_file else None
                otros_datos_val_from_file = otros_datos_val_from_file if otros_datos_val_from_file != "" else None

                peso_val = row.get('peso')
                peso_val = int(peso_val) if peso_val and str(peso_val).strip().isdigit() else None
                
                cantidad_radares_val = row.get('cantidad_radares')
                cantidad_radares_val = int(cantidad_radares_val) if cantidad_radares_val and str(cantidad_radares_val).strip().isdigit() else None
                
                processed_rows.append({
                    'area': row.get('area'),
                    'especie': especie_val_from_file,
                    'centro': centro_nombre, 
                    'peso': peso_val,
                    'sistema': sistema_upper_from_file,
                    'monitoreados': row.get('monitoreados'),
                    'fecha_apertura': fecha_apertura_val_from_file,
                    'fecha_cierre': fecha_cierre_val_from_file, 
                    'prox_apertura': prox_apertura_val_from_file, 
                    'ponton': ponton_val_from_file, 
                    'ex_ponton': ex_ponton_val_from_file, 
                    'cantidad_radares': cantidad_radares_val,
                    'nro_gps_ponton': nro_gps_ponton_val_from_file, 
                    'otros_datos': otros_datos_val_from_file
                })
            except Exception as e:
                print(f"Error al pre-procesar la fila: {row}. Error: {e}")
                skip_count += 1
                continue
        
        # --- Lógica de inserción condicional ---
        if not processed_rows:
            raise HTTPException(status_code=400, detail=f"El archivo '{nombre_reporte}' no contiene registros válidos para insertar. Se han omitido {skip_count} filas.")

        # Si hay filas válidas, inserta el reporte
        sql_insert_reporte = "INSERT INTO `reportes` (`fecha_subida`, `nombre_reporte`) VALUES (NOW(), %s)"
        cursor.execute(sql_insert_reporte, (nombre_reporte,))
        db.commit()
        id_reporte = cursor.lastrowid
        
        insert_count = 0
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`, `id_reporte`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        for row_data in processed_rows:
            try:
                # Verificar duplicados para este reporte recién creado
                check_sql = "SELECT centro FROM centros WHERE centro = %s AND `id_reporte` = %s"
                cursor.execute(check_sql, (row_data['centro'], id_reporte))
                existing_centro = cursor.fetchone()

                if existing_centro:
                    print(f"Advertencia: El centro '{row_data['centro']}' ya existe para el reporte {id_reporte}. Se omite la inserción.")
                    skip_count += 1 # Contamos los duplicados que se omiten en esta fase
                    continue

                val = (
                    row_data['area'], row_data['especie'], row_data['centro'], 
                    row_data['peso'],
                    row_data['sistema'],
                    row_data['monitoreados'],
                    row_data['fecha_apertura'],
                    row_data['fecha_cierre'], 
                    row_data['prox_apertura'], 
                    row_data['ponton'], 
                    row_data['ex_ponton'], 
                    row_data['cantidad_radares'],
                    row_data['nro_gps_ponton'], 
                    row_data['otros_datos'], 
                    id_reporte
                )
                cursor.execute(sql, val)
                insert_count += 1
            except Exception as e:
                print(f"Error al insertar fila procesada: {row_data}. Error: {e}")
                skip_count += 1 # Contar también errores de inserción
                continue
                
        db.commit()
        return {"message": f"Reporte '{nombre_reporte}' (ID: {id_reporte}) creado. Se han insertado {insert_count} centros. Se han omitido {skip_count} filas (errores o duplicados)."}
        
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

# Endpoint para obtener todos los centros
@app.get("/centros/")
async def get_centros():
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

# Endpoint para obtener todos los IDs de reportes
@app.get("/reportes/")
async def get_reportes():
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

# Endpoint para obtener todos los centros de un reporte específico
@app.get("/reportes/{id_reporte}")
async def get_reporte_by_id(id_reporte: int):
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