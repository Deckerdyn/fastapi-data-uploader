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
        INSERT INTO centros (`area`, `especie`, `centro`, `tv`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `transferencias`, `otros_datos`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        # Normalización de los datos antes de la inserción
        sistema_upper_val = centro.sistema.upper() if centro.sistema and centro.sistema.strip() else None
        val = (
            centro.area,
            centro.especie if centro.especie and centro.especie.strip() else None,
            centro.centro,
            centro.tv, # Nueva columna
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
            centro.transferencias if centro.transferencias and centro.transferencias.strip() else None, # Nueva columna
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

async def process_upload_file(file_bytes: bytes, file_extension: str, filename: str) -> dict:
    """
    Procesa un archivo CSV o XLSX para cargar datos de centros en la base de datos.
    Implementa transacciones para asegurar que tanto el reporte como los centros
    se inserten de forma conjunta, o se reviertan si hay un error.

    Args:
        file_bytes (bytes): El contenido binario del archivo subido.
        file_extension (str): La extensión del archivo (ej. '.csv', '.xlsx').
        filename (str): El nombre original del archivo.

    Returns:
        dict: Un mensaje de éxito con el ID del reporte y el número de filas insertadas.

    Raises:
        HTTPException: Si el archivo es inválido, no se encuentran filas válidas,
                       o ocurre un error durante la operación de base de datos.
    """
    db = None
    cursor = None
    id_reporte = None
    skip_count = 0 # Inicializar skip_count aquí para que esté disponible en caso de errores tempranos

    try:
        db = get_db_connection()
        db.autocommit = False  # Desactiva el auto-commit para controlar la transacción manualmente

        csv_reader = None
        if file_extension == '.xlsx':
            try:
                file_stream = io.BytesIO(file_bytes)
                
                # Leer el archivo temporalmente para encontrar la fila del encabezado 'Centro'
                df_temp = pd.read_excel(file_stream, sheet_name="Todos los centros", header=None)
                
                header_row_index = -1
                for i, row in df_temp.iterrows():
                    # Buscar la primera fila que contenga 'Centro' (ignorando mayúsculas/minúsculas y espacios)
                    if any(isinstance(val, str) and val.strip().lower() == 'centro' for val in row.values):
                        header_row_index = i
                        break
                
                if header_row_index == -1:
                    raise HTTPException(status_code=400, detail="No se pudo encontrar la fila de encabezado 'Centro' en el archivo Excel.")
                
                file_stream.seek(0) # Restablece el puntero del stream para leer de nuevo desde el principio
                df = pd.read_excel(file_stream, sheet_name="Todos los centros", header=header_row_index)

                # Limpia y normaliza los nombres de las columnas
                df.columns = df.columns.astype(str).str.strip().str.replace('.', '', regex=False).str.replace(' ', '_', regex=False).str.lower()
                
                # Elimina columnas que no tienen nombre o están vacías después de la normalización
                df = df.loc[:, df.columns.notna()]
                df = df.loc[:, df.columns != '']
                
                # Elimina filas completamente vacías (donde todos los valores son NaN)
                df.dropna(how='all', inplace=True)

                # Convierte el DataFrame a un formato CSV en memoria para usar DictReader
                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=False, sep=';', encoding='utf-8')
                csv_buffer.seek(0)
                csv_reader = csv.DictReader(csv_buffer, delimiter=';')

            except Exception as e:
                # Captura errores específicos de lectura de Excel
                raise HTTPException(status_code=400, detail=f"Error al leer el archivo de Excel: {e}")
        else: # Es un archivo .csv
            # Decodificar el contenido del archivo con 'utf-8-sig' para manejar el BOM (Byte Order Mark)
            # y 'errors=ignore' para omitir caracteres que no puedan ser decodificados
            csv_file = io.StringIO(file_bytes.decode('utf-8-sig', errors='ignore'))
            csv_reader = csv.DictReader(csv_file, delimiter=';') 

        rows_to_insert = []
        for row in csv_reader:
            try:
                # Normalización y preparación de los datos de cada fila
                centro_nombre = row.get('centro')
                if not centro_nombre or not str(centro_nombre).strip():
                    print("Advertencia: Se encontró una fila sin nombre de centro. Se omite.")
                    skip_count += 1
                    continue
                
                # Si la fila es el encabezado 'centro' nuevamente (puede ocurrir en algunos CSVs mal formados)
                if centro_nombre.strip().lower() == 'centro':
                    print(f"Advertencia: Se omitió la fila de encabezado: {row}")
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

                pontón_key = 'pontón' if 'pontón' in row else 'ponton' # Soporte para 'pontón' o 'ponton'
                ponton_val = row.get(pontón_key)
                ponton_val = ponton_val if ponton_val and str(ponton_val).strip() else None

                ex_pontón_key = 'ex_pontón' if 'ex_pontón' in row else 'ex_ponton' # Soporte para 'ex_pontón' o 'ex_ponton'
                ex_ponton_val = row.get(ex_pontón_key)
                ex_ponton_val = ex_ponton_val if ex_ponton_val and str(ex_ponton_val).strip() else None

                nro_gps_pontón_key = 'nro_gps_pontón' if 'nro_gps_pontón' in row else 'nro_gps_ponton' # Soporte para 'nro_gps_pontón' o 'nro_gps_ponton'
                nro_gps_ponton_val = row.get(nro_gps_pontón_key)
                nro_gps_ponton_val = nro_gps_ponton_val if nro_gps_ponton_val and str(nro_gps_ponton_val).strip() else None

                otros_datos_val = row.get('otros_datos')
                otros_datos_val = otros_datos_val if otros_datos_val and str(otros_datos_val).strip() else None

                # Nuevas columnas
                tv_val = row.get('tv')
                tv_val = int(tv_val) if tv_val and str(tv_val).strip().isdigit() else None

                transferencias_val = row.get('transferencias')
                transferencias_val = transferencias_val if transferencias_val and str(transferencias_val).strip() else None


                rows_to_insert.append((
                    row.get('area'), 
                    especie_val, 
                    centro_nombre,
                    tv_val, # Nuevo valor
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
                    transferencias_val, # Nuevo valor
                    otros_datos_val,
                ))
            except Exception as e:
                # Captura cualquier error durante la preparación de la fila y lo registra
                print(f"Error al preparar la fila para la inserción: {row}. Error: {e}")
                skip_count += 1
                continue
        
        # --- Inicio de la Lógica Transaccional ---
        # Si no hay filas válidas después de procesar el archivo, se lanza una excepción
        if not rows_to_insert:
            raise HTTPException(status_code=400, detail=f"No se encontraron filas válidas para insertar en el archivo. Se han omitido {skip_count} filas.")

        cursor = db.cursor()
        nombre_reporte = filename.rsplit('.', 1)[0]
        
        # 1. Inserta el registro del reporte
        sql_insert_reporte = "INSERT INTO `reportes` (`fecha_subida`, `nombre_reporte`) VALUES (NOW(), %s)"
        cursor.execute(sql_insert_reporte, (nombre_reporte,))
        id_reporte = cursor.lastrowid # Obtiene el ID del reporte recién insertado

        # 2. Prepara los valores de los centros con el id_reporte
        final_insert_values = [row_data + (id_reporte,) for row_data in rows_to_insert]
        sql_insert_centros = """
        INSERT INTO centros (`area`, `especie`, `centro`, `tv`, `peso`, `sistema`, `monitoreados`, `fecha_apertura`, `fecha_cierre`, `prox_apertura`, `ponton`, `ex_ponton`, `cantidad_radares`, `nro_gps_ponton`, `transferencias`, `otros_datos`, `id_reporte`)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # 3. Inserta los centros en un solo lote (executemany)
        cursor.executemany(sql_insert_centros, final_insert_values)
        insert_count = cursor.rowcount

        # 4. Si todo lo anterior fue exitoso, realiza el commit para guardar los cambios permanentemente
        db.commit()

        return {"message": f"Reporte '{nombre_reporte}' (ID: {id_reporte}) creado. Se han insertado {insert_count} filas. Se han omitido {skip_count} filas inválidas."}
    
    except HTTPException as http_exc:
        # Si se lanza una HTTPException (ej. archivo inválido, no hay filas válidas)
        if db and db.is_connected():
            db.rollback() # Deshace cualquier cambio, incluyendo el reporte si ya se insertó
        raise http_exc # Relanza la excepción HTTP para que FastAPI la maneje
    except mysql.connector.Error as err:
        # Captura errores específicos de la base de datos
        if db and db.is_connected():
            db.rollback() # Deshace todos los cambios de la transacción
        raise HTTPException(status_code=500, detail=f"Error al insertar datos en la base de datos: {err}")
    except Exception as e:
        # Captura cualquier otro error inesperado
        if db and db.is_connected():
            db.rollback() # Deshace todos los cambios de la transacción
        raise HTTPException(status_code=500, detail=f"Error inesperado al procesar el archivo: {e}")
    finally:
        # Asegúrate de cerrar el cursor y la conexión a la base de datos en todos los casos
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

