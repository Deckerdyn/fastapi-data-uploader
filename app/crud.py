# app/crud.py
import io
import csv
import os
import pandas as pd
import mysql.connector
from fastapi import HTTPException
from app.database import get_db_connection
from app.models import Centro

def insert_centro(centro: Centro):
    """Inserta una nueva entrada de centro en la base de datos."""
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        sql = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Normalización de los datos antes de la inserción
        sistema_upper_val = centro.sistema.upper() if centro.sistema and centro.sistema.strip() else None
        val = (
            centro.area,
            centro.especie if centro.especie and centro.especie.strip() else None,
            centro.centro,
            centro.peso,
            sistema_upper_val,
            centro.monitoreados if centro.monitoreados and centro.monitoreados.strip() else None,
            centro.fecha_apertura,
            centro.fecha_cierre,
            centro.prox_apertura,
            centro.ponton if centro.ponton and centro.ponton.strip() else None,
            centro.ex_ponton if centro.ex_ponton and centro.ex_ponton.strip() else None,
            centro.cantidad_radares,
            centro.nro_gps_ponton if centro.nro_gps_ponton and centro.nro_gps_ponton.strip() else None,
            centro.otros_datos if centro.otros_datos and centro.otros_datos.strip() else None
        )
        cursor.execute(sql, val)
        db.commit()
        return {"message": "Datos insertados correctamente"}
    except mysql.connector.Error as err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al insertar datos: {err}")
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

async def process_upload_file(file_bytes: bytes, file_extension: str, filename: str):
    """Procesa el contenido de un archivo CSV o XLSX para su inserción."""
    db = None
    cursor = None
    nombre_reporte = os.path.splitext(filename)[0]
    id_reporte = None
    insert_count = 0
    skip_count = 0

    try:
        db = get_db_connection()
        cursor = db.cursor()

        if file_extension == '.xlsx':
            try:
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
            csv_file = io.StringIO(file_bytes.decode('utf-8-sig', errors='ignore'))
            csv_reader = csv.DictReader(csv_file, delimiter=';')

        sql_insert_reporte = "INSERT INTO `reportes` (`fecha_subida`, `nombre_reporte`) VALUES (NOW(), %s)"
        cursor.execute(sql_insert_reporte, (nombre_reporte,))
        db.commit()
        id_reporte = cursor.lastrowid

        rows_to_insert = []
        sql_insert_centro = """
        INSERT INTO centros (`area`, `especie`, `centro`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `otros_datos`, `id_reporte`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        for row in csv_reader:
            try:
                centro_nombre = row.get('centro')
                if not centro_nombre or not str(centro_nombre).strip():
                    skip_count += 1
                    continue
                if centro_nombre.strip().lower() == 'centro':
                    skip_count += 1
                    continue
                
                sistema_from_file = row.get('sistema')
                sistema_upper_from_file = sistema_from_file.upper() if sistema_from_file and str(sistema_from_file).strip() else None
                especie_from_file = row.get('especie')
                especie_val = especie_from_file if especie_from_file and str(especie_from_file).strip() else None
                peso_val = row.get('peso')
                peso_val = int(peso_val) if peso_val and str(peso_val).strip().isdigit() else None
                cantidad_radares_val = row.get('cantidad_radares')
                cantidad_radares_val = int(cantidad_radares_val) if cantidad_radares_val and str(cantidad_radares_val).strip().isdigit() else None
                monitoreados_val = row.get('monitoreados')
                monitoreados_val = monitoreados_val if monitoreados_val and str(monitoreados_val).strip() else None
                ponton_val = row.get('pontón') if row.get('pontón') else row.get('ponton')
                ponton_val = ponton_val if ponton_val and str(ponton_val).strip() else None
                ex_ponton_val = row.get('ex_pontón') if row.get('ex_pontón') else row.get('ex_ponton')
                ex_ponton_val = ex_ponton_val if ex_ponton_val and str(ex_ponton_val).strip() else None
                nro_gps_ponton_val = row.get('nro_gps_pontón') if row.get('nro_gps_pontón') else row.get('nro_gps_ponton')
                nro_gps_ponton_val = nro_gps_ponton_val if nro_gps_ponton_val and str(nro_gps_ponton_val).strip() else None
                otros_datos_val = row.get('otros_datos')
                otros_datos_val = otros_datos_val if otros_datos_val and str(otros_datos_val).strip() else None

                rows_to_insert.append((
                    row.get('area'), especie_val, centro_nombre, peso_val,
                    sistema_upper_from_file, monitoreados_val,
                    row.get('fecha_apertura') if row.get('fecha_apertura') and str(row.get('fecha_apertura')).strip() else None,
                    row.get('fecha_cierre') if row.get('fecha_cierre') and str(row.get('fecha_cierre')).strip() else None,
                    row.get('prox_apertura') if row.get('prox_apertura') and str(row.get('prox_apertura')).strip() else None,
                    ponton_val, ex_ponton_val, cantidad_radares_val, nro_gps_ponton_val, otros_datos_val, id_reporte,
                ))
            except Exception as e:
                skip_count += 1
                continue

        if not rows_to_insert:
            db.rollback()
            raise HTTPException(status_code=400, detail=f"No se encontraron filas válidas para insertar en el archivo. Se han omitido {skip_count} filas.")

        cursor.executemany(sql_insert_centro, rows_to_insert)
        insert_count = cursor.rowcount
        db.commit()

        return {"message": f"Reporte '{nombre_reporte}' (ID: {id_reporte}) creado. Se han insertado {insert_count} filas. Se han omitido {skip_count} filas inválidas."}

    except mysql.connector.Error as err:
        if db and db.is_connected():
            db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al insertar datos en la base de datos: {err}")
    except HTTPException as http_exc:
        if db and db.is_connected() and id_reporte:
            db.rollback()
        raise http_exc
    except Exception as e:
        if db and db.is_connected():
            db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inesperado al procesar el archivo: {e}")
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

def get_all_centros():
    """Obtiene todos los centros de la base de datos."""
    db = None
    cursor = None
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
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

def get_all_reportes():
    """Obtiene todos los reportes de la base de datos."""
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id_reporte, nombre_reporte, fecha_subida FROM reportes")
        results = cursor.fetchall()
        return results
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error al obtener datos de reportes: {err}")
    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

def get_centros_by_reporte_id(id_reporte: int):
    """Obtiene todos los centros asociados a un reporte específico."""
    db = None
    cursor = None
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
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()