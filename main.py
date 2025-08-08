# main.py
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import mysql.connector
import csv
import io
import os
from dotenv import load_dotenv
import pandas as pd
import openpyxl

# Carga las variables de entorno del archivo .env
load_dotenv()

app = FastAPI()

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
        val = (
            centro.area, centro.especie, centro.centro, centro.peso, centro.sistema, centro.monitoreados,
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

        # Paso 1: Leer el archivo y convertir a CSV si es Excel
        if file_extension == '.xlsx':
            try:
                # Usar pandas para leer el archivo de Excel. Ya no se usa skiprows.
                df = pd.read_excel(file.file, sheet_name="Todos los centros", engine='openpyxl')
                csv_buffer = io.StringIO()
                # Se guarda en un buffer en formato CSV con el delimitador y la codificación correctos
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
                centro_nombre = row.get('Centro')
                if not centro_nombre:
                    print("Error: Se encontró una fila sin nombre de centro. Se omite.")
                    continue

                check_sql = "SELECT centro FROM centros WHERE centro = %s AND `id_reporte` = %s"
                cursor.execute(check_sql, (centro_nombre, id_reporte))
                existing_centro = cursor.fetchone()

                if existing_centro:
                    print(f"Advertencia: El centro '{centro_nombre}' ya existe para el reporte {id_reporte}. Se omite la inserción.")
                    skip_count += 1
                    continue

                val = (
                    row.get('Area'), row.get('Especie'), row.get('Centro'), 
                    int(row.get('Peso')) if row.get('Peso') else None, 
                    row.get('Sistema'), row.get('Monitoreados'),
                    row.get('Fecha Apertura') if row.get('Fecha Apertura') else None,
                    row.get('Fecha Cierre') if row.get('Fecha Cierre') else None, 
                    row.get('Prox. Apertura') if row.get('Prox. Apertura') else None, 
                    row.get('Pontón'),
                    row.get('Ex Pontón'),
                    int(row.get('Cantidad Radares')) if row.get('Cantidad Radares') else None,
                    row.get('Nro. GPS Pontón'),
                    row.get('Otros Datos'),
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

# Endpoint para obtener todos los centros
@app.get("/centros/")
async def get_centros():
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM centros")
        results = cursor.fetchall()
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
        
        return centros
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros del reporte: {err}")
    finally:
        if 'db' in locals() and db.is_connected():
            cursor.close()
            db.close()