# main.py
import os
from pathlib import Path
import shutil
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import Response, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pipeline import (
    process_image, 
    process_pdf, 
    process_excel,  
    process_powerpoint,  # Add this import
    format_final_output, 
    UPLOAD_DIR,
    REDACTED_DIR,
    redact_text_in_image, 
    format_technical_analysis,
    format_for_html_display,
    analyzer
)

app = FastAPI(title="File Cleansing and Analysis AI Pipeline")

# Mount static files for CSS and JS
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Mount redacted files directory so they can be downloaded
app.mount("/redacted", StaticFiles(directory="redacted_files"), name="redacted")

# Serve the main HTML page
@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_path = Path("frontend/index.html")
    if (html_path.exists()):
        return FileResponse(html_path)
    else:
        raise HTTPException(status_code=404, detail="Frontend not found")

# Add favicon route to prevent 404 errors
@app.get("/favicon.ico")
async def favicon():
    favicon_path = Path("frontend/favicon.ico")
    if (favicon_path.exists()):
        return FileResponse(favicon_path)
    else:
        return Response(status_code=204)

@app.post("/process-file/")
async def create_upload_file(file: UploadFile = File(...)):
    """
    Accepts a file, saves it, processes it based on type,
    and returns redaction/analysis results in table format.
    """
    file_ext = Path(file.filename).suffix.lower()
    
    # Save the uploaded file
    file_path = UPLOAD_DIR / file.filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        if file_ext in [".png", ".jpg", ".jpeg"]:
            print("Processing image file...")
            # Use the new OCR-based redaction and analysis pipeline
            redacted_file, extracted_text = redact_text_in_image(file_path, analyzer)
            
            if not extracted_text:
                raise HTTPException(status_code=400, detail="Unable to process image content")
            
            print(f"Extracted text from image: {extracted_text[:200]}...")
            
            # Format with file path context
            formatted_analysis = format_final_output(
                extracted_text, 
                file_path=file_path,
                is_technical=True
            )
            
        elif file_ext == ".pdf":
            print("Processing PDF file...")
            redacted_file, analysis = process_pdf(file_path)
            
            if not analysis or "Error" in str(analysis):
                raise HTTPException(status_code=400, detail=f"PDF processing failed: {analysis}")
            
            print(f"PDF analysis text length: {len(analysis)}")
            print(f"PDF analysis preview: {analysis[:300]}...")
            
            # Format the analysis into the final structure with file context
            formatted_analysis = format_final_output(
                analysis,
                file_path=file_path,
                is_technical=True
            )
            
        elif file_ext in [".xlsx", ".xls"]:
            print("Processing Excel file...")
            redacted_file, analysis = process_excel(file_path)
            
            if not analysis or "Error" in str(analysis):
                raise HTTPException(status_code=400, detail=f"Excel processing failed: {analysis}")

            print(f"Excel analysis text length: {len(analysis)}")
            print(f"Excel analysis preview: {analysis[:300]}...")
            
            # Format the analysis into the final structure with file context
            formatted_analysis = format_final_output(
                analysis,
                file_path=file_path,
                is_technical=True
            )
            
        elif file_ext in [".ppt", ".pptx"]:
            print("Processing PowerPoint file...")
            redacted_file, analysis = process_powerpoint(file_path)
            
            if not analysis or "Error" in str(analysis):
                raise HTTPException(status_code=400, detail=f"PowerPoint processing failed: {analysis}")

            print(f"PowerPoint analysis text length: {len(analysis)}")
            print(f"PowerPoint analysis preview: {analysis[:300]}...")
            
            # Format the analysis into the final structure with file context
            formatted_analysis = format_final_output(
                analysis,
                file_path=file_path,
                is_technical=True
            )
            
        else:
            supported_formats = [".png", ".jpg", ".jpeg", ".pdf", ".xlsx", ".xls", ".ppt", ".pptx"]
            raise HTTPException(
                status_code=400, 
                detail=f"File type '{file_ext}' not supported. Supported formats: {', '.join(supported_formats)}"
            )
        
        # Convert redacted file path to URL path
        if redacted_file:
            redacted_filename = Path(redacted_file).name
            redacted_url = f"/redacted/{redacted_filename}"
        else:
            redacted_url = None
        
        print(f"Formatted analysis: {formatted_analysis[:200] if formatted_analysis else 'None'}...")
        
        # Convert to HTML for better web display
        if formatted_analysis and formatted_analysis.strip().startswith('|'):
            html_analysis = format_for_html_display(formatted_analysis)
        else:
            html_analysis = f"<pre>{formatted_analysis}</pre>" if formatted_analysis else "<p>No analysis available</p>"
        
        print(f"Processing completed successfully")
        print(f"Formatted analysis length: {len(formatted_analysis) if formatted_analysis else 0}")
        print(f"HTML analysis length: {len(html_analysis) if html_analysis else 0}")
        
        return {
            "original_filename": file.filename,
            "redacted_file_path": redacted_url,
            "analysis": formatted_analysis,
            "html_analysis": html_analysis
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log the error for debugging
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error during processing: {str(e)}")
        
    finally:
        # Clean up the uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)