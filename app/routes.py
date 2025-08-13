# app/routes.py
import os
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from app.models import Centro, User
from app.auth import get_current_user_token
from app import crud

centros_router = APIRouter()

@centros_router.post("/centros/")
async def create_centro(centro: Centro, current_user: User = Depends(get_current_user_token)):
    """
    Endpoint para recibir y guardar los datos de una sola entrada.
    Requiere autenticación con token.
    """
    return crud.insert_centro(centro)

@centros_router.post("/upload-centros/")
async def upload_centros_csv(file: UploadFile = File(...), current_user: User = Depends(get_current_user_token)):
    """
    Endpoint para recibir y procesar archivos CSV o XLSX.
    Requiere autenticación con token.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No se ha proporcionado un archivo.")

    file_extension = os.path.splitext(file.filename)[1].lower()

    if file_extension not in ['.csv', '.xlsx']:
        raise HTTPException(status_code=400, detail="El archivo debe ser de tipo .csv o .xlsx")
    
    file_bytes = await file.read()
    return await crud.process_upload_file(file_bytes, file_extension, file.filename)

@centros_router.get("/centros/")
async def get_centros(current_user: User = Depends(get_current_user_token)):
    """
    Endpoint para obtener todos los centros.
    Requiere autenticación con token.
    """
    return crud.get_all_centros()

@centros_router.get("/reportes/")
async def get_reportes(current_user: User = Depends(get_current_user_token)):
    """
    Endpoint para obtener todos los IDs y nombres de reportes.
    Requiere autenticación con token.
    """
    return crud.get_all_reportes()

@centros_router.get("/reportes/{id_reporte}")
async def get_reporte_by_id(id_reporte: int, current_user: User = Depends(get_current_user_token)):
    """
    Endpoint para obtener todos los centros de un reporte específico.
    Requiere autenticación con token.
    """
    return crud.get_centros_by_reporte_id(id_reporte)