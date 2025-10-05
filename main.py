# main.py

import os
from pathlib import Path
import shutil
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pipeline import (
    process_image, 
    process_pdf, 
    format_final_output, 
    UPLOAD_DIR,
    redact_text_in_image, 
    format_technical_analysis, 
    analyzer
)

app = FastAPI(title="File Cleansing and Analysis AI Pipeline")

# Mount static files for CSS and JS
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Serve the main HTML page
@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = Path("frontend/index.html")
    if html_path.exists():
        return FileResponse(html_path)
    else:
        raise HTTPException(status_code=404, detail="Frontend not found")

# Add favicon route to prevent 404 errors
@app.get("/favicon.ico")
async def favicon():
    favicon_path = Path("frontend/favicon.ico")
    if favicon_path.exists():
        return FileResponse(favicon_path)
    else:
        # Return a 204 No Content if favicon doesn't exist
        return Response(status_code=204)

@app.post("/process-file/")
async def create_upload_file(file: UploadFile = File(...)):
    """
    Accepts a file, saves it, processes it based on type,
    and returns redaction/analysis results.
    """
    file_ext = Path(file.filename).suffix.lower()
    
    # Save the uploaded file
    file_path = UPLOAD_DIR / file.filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        if file_ext in [".png", ".jpg", ".jpeg"]:
            # Use the new OCR-based redaction and analysis pipeline
            redacted_file, extracted_text = redact_text_in_image(file_path, analyzer)
            formatted_analysis = format_technical_analysis(extracted_text)
        elif file_ext == ".pdf":
            redacted_file, analysis = process_pdf(file_path)
            # Format the analysis into the final structure
            formatted_analysis = format_final_output(analysis)
        # TODO: Add handlers for .xlsx and .pptx
        # elif file_ext == ".xlsx":
        #     redacted_file, analysis = process_excel(file_path)
        else:
            raise HTTPException(status_code=400, detail=f"File type '{file_ext}' not supported.")
        
        return {
            "original_filename": file.filename,
            "redacted_file_path": str(redacted_file),
            "analysis": formatted_analysis
        }
    except Exception as e:
        # Log the error for debugging
        print(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during file processing.")
    finally:
        # Clean up the uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)