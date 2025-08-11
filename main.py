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

                # Convierte el valor de 'especie' a None si es una cadena vacía o solo espacios
                especie_from_file = row.get('especie')
                especie_val_from_file = especie_from_file.strip() if especie_from_file else None
                especie_val_from_file = especie_val_from_file if especie_val_from_file != "" else None

                # Convierte los valores de campos opcionales a None si son cadenas vacías o solo espacios
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


                # Convertir los valores a los tipos correctos antes de la inserción
                peso_val = row.get('peso')
                peso_val = int(peso_val) if peso_val and str(peso_val).strip().isdigit() else None
                
                cantidad_radares_val = row.get('cantidad_radares')
                cantidad_radares_val = int(cantidad_radares_val) if cantidad_radares_val and str(cantidad_radares_val).strip().isdigit() else None
                
                val = (
                    row.get('area'), especie_val_from_file, row.get('centro'), 
                    peso_val,
                    sistema_upper_from_file, # Usa el valor en mayúsculas
                    row.get('monitoreados'),
                    fecha_apertura_val_from_file,
                    fecha_cierre_val_from_file, 
                    prox_apertura_val_from_file, 
                    ponton_val_from_file, 
                    ex_ponton_val_from_file, 
                    cantidad_radares_val,
                    nro_gps_ponton_val_from_file, 
                    otros_datos_val_from_file, 
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
