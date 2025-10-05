# pipeline.py
import os
from pathlib import Path
import cv2
import pytesseract
from PIL import Image
import pandas as pd
from ultralytics import YOLO
from langchain_community.llms import CTransformers
from langchain_community.chat_models import ChatLlamaCpp
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.messages import HumanMessage
import pdfplumber
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
import numpy as np

# --- Configuration ---
UPLOAD_DIR = Path("uploads")
REDACTED_DIR = Path("redacted_files")
MODEL_DIR = Path("models")

# Ensure directories exist
UPLOAD_DIR.mkdir(exist_ok=True)
REDACTED_DIR.mkdir(exist_ok=True)

# --- Global Variables for Models (initialized on first use) ---
_yolo_model = None
_llava_model = None
_llm = None
_analyzer = None
_anonymizer = None

# --- Model Loading Functions (Lazy Loading) ---
def get_yolo_model():
    """Load YOLO model (lazy loading)"""
    global _yolo_model
    if _yolo_model is None:
        YOLO_MODEL_PATH = "best.pt"
        if not Path(YOLO_MODEL_PATH).exists():
            print(f"Warning: YOLO model not found at {YOLO_MODEL_PATH}")
            return None
        _yolo_model = YOLO(YOLO_MODEL_PATH)
    return _yolo_model

def get_llava_model():
    """Load LLaVA model (lazy loading)"""
    global _llava_model
    if _llava_model is None:
        try:
            _llava_model = ChatLlamaCpp(
                model_path=str(MODEL_DIR / "ggml-model-q5_k.gguf"),
                chat_format="llava-1-5",
                model_kwargs={
                    "clip_model_path": str(MODEL_DIR / "mmproj-model-f16.gguf")
                },
                n_gpu_layers=0,
                n_ctx=2048,
                verbose=False,
            )
        except Exception as e:
            print(f"Warning: Could not load LLaVA model: {e}")
            return None
    return _llava_model

def get_llm():
    """Load Mistral LLM (lazy loading)"""
    global _llm
    if _llm is None:
        try:
            _llm = CTransformers(
                model=str(MODEL_DIR / "mistral-7b-instruct-v0.2.Q5_K_M.gguf"),
                model_type="mistral",
                config={'context_length': 8192, 'gpu_layers': 0}
            )
        except Exception as e:
            print(f"Warning: Could not load Mistral LLM: {e}")
            return None
    return _llm

def get_analyzer():
    """Get Presidio analyzer with comprehensive PII and technical data recognizers"""
    global _analyzer
    if (_analyzer is None):
        # AWS and Cloud Infrastructure Patterns
        aws_patterns = [
            Pattern(name="AWS_ARN", regex=r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-\/\:\_]+", score=0.95),
            Pattern(name="AWS_ROLE_ID", regex=r"A[IKR][A-Z0-9]{18,}", score=0.9),
            Pattern(name="AWS_ACCOUNT", regex=r"\b\d{12}\b", score=0.85),
            Pattern(name="IP_CIDR", regex=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b", score=0.95),
            Pattern(name="IP_ADDRESS", regex=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", score=0.9),
            Pattern(name="MAC_ADDRESS", regex=r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", score=0.9),
        ]
        
        # Network and Security Patterns
        network_patterns = [
            Pattern(name="PORT_RANGE", regex=r"\b(tcp|udp|icmp):\d{1,5}(-\d{1,5})?\b", score=0.85),
            Pattern(name="PORT_SINGLE", regex=r"\b(port|Port)\s*:?\s*\d{1,5}\b", score=0.8),
            Pattern(name="PROTOCOL", regex=r"\b(tcp|udp|icmp|ssh|rdp|sftp):\d+\b", score=0.85),
        ]
        
        # File paths and sensitive locations
        path_patterns = [
            Pattern(name="FILE_PATH", regex=r"file://[a-zA-Z0-9\-\_\./]+", score=0.8),
            Pattern(name="UNIX_PATH", regex=r"/[a-zA-Z0-9\-\_/]+\.[a-zA-Z]{2,4}", score=0.75),
        ]
        
        # Dates and timestamps that might be sensitive
        date_patterns = [
            Pattern(name="ISO_DATETIME", regex=r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", score=0.7),
            Pattern(name="TIMESTAMP", regex=r"\d{2}/\d{2}/\d{2,4}", score=0.6),
        ]
        
        # Names and identifiers
        name_patterns = [
            Pattern(name="ROLE_NAME", regex=r"(role|Role)[-_]?[nN]ame[\"']?\s*:?\s*[\"']?([A-Za-z0-9\-\_]+)", score=0.8),
            Pattern(name="GROUP_NAME", regex=r"(group|Group)[-_]?[nN]ame[\"']?\s*:?\s*[\"']?([A-Za-z0-9\-\_]+)", score=0.8),
            # Original pattern, good for single-line rule names
            Pattern(name="FIREWALL_RULE_NAME", regex=r"\bdefault-[a-z\-]+\b", score=0.9),
            # New, more flexible pattern for multi-line or partial rule names
            Pattern(name="FIREWALL_RULE_PREFIX", regex=r"\b(default-allow-|default-deny-)\b", score=0.85),
        ]
        
        # Session and duration
        duration_patterns = [
            Pattern(name="SESSION_DURATION", regex=r"(session|Session)[-_]?[dD]uration[\"']?\s*:?\s*\d+", score=0.75),
            Pattern(name="MAX_DURATION", regex=r"max[-_]?session[-_]?duration\s*\d+", score=0.8),
        ]
        
        # Create recognizers
        aws_recognizer = PatternRecognizer(
            supported_entity="AWS_IDENTIFIER",
            patterns=aws_patterns,
            name="AWS Recognizer"
        )
        
        network_recognizer = PatternRecognizer(
            supported_entity="NETWORK_INFO",
            patterns=network_patterns,
            name="Network Recognizer"
        )
        
        path_recognizer = PatternRecognizer(
            supported_entity="FILE_PATH",
            patterns=path_patterns,
            name="Path Recognizer"
        )
        
        date_recognizer = PatternRecognizer(
            supported_entity="TIMESTAMP",
            patterns=date_patterns,
            name="Date Recognizer"
        )
        
        name_recognizer = PatternRecognizer(
            supported_entity="IDENTIFIER_NAME",
            patterns=name_patterns,
            name="Name Recognizer"
        )
        
        duration_recognizer = PatternRecognizer(
            supported_entity="DURATION",
            patterns=duration_patterns,
            name="Duration Recognizer"
        )
        
        # Initialize analyzer with all recognizers
        _analyzer = AnalyzerEngine()
        _analyzer.registry.add_recognizer(aws_recognizer)
        _analyzer.registry.add_recognizer(network_recognizer)
        _analyzer.registry.add_recognizer(path_recognizer)
        _analyzer.registry.add_recognizer(date_recognizer)
        _analyzer.registry.add_recognizer(name_recognizer)
        _analyzer.registry.add_recognizer(duration_recognizer)
    
    return _analyzer

def get_anonymizer():
    """Get Presidio anonymizer"""
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


# --- Main Processing Function (This is what main.py should import) ---
def process_image(file_path: Path, is_scenic: bool = False):
    """
    Main function to process images - handles both scenic and text-heavy images
    
    Args:
        file_path: Path to the image file
        is_scenic: If True, uses YOLO+LLaVA for scenic images. 
                   If False, uses OCR+Presidio for text-heavy images
    
    Returns:
        tuple: (redacted_file_path, analysis_text)
    """
    if is_scenic:
        return process_scenic_image(file_path)
    else:
        return process_text_image(file_path, get_analyzer())


def process_file(file_path: Path, file_type: str = None):
    """
    Universal file processor - automatically detects and processes any file type
    
    Args:
        file_path: Path to the file
        file_type: Optional file type hint ('image', 'pdf', 'excel', etc.)
    
    Returns:
        dict: {
            'redacted_path': Path to redacted file,
            'analysis': Analysis text,
            'file_type': Detected file type
        }
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Auto-detect file type
    ext = file_path.suffix.lower()
    
    if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.tiff']:
        # Determine if scenic or text-heavy
        # Simple heuristic: if image has a lot of text (OCR confidence), it's text-heavy
        is_scenic = is_image_scenic(file_path)
        redacted_path, analysis = process_image(file_path, is_scenic=is_scenic)
        return {
            'redacted_path': redacted_path,
            'analysis': analysis,
            'file_type': 'scenic_image' if is_scenic else 'text_image'
        }
    
    elif ext == '.pdf':
        redacted_path, analysis = process_pdf(file_path)
        return {
            'redacted_path': redacted_path,
            'analysis': analysis,
            'file_type': 'pdf'
        }
    
    elif ext in ['.xlsx', '.xls']:
        redacted_path, analysis = process_excel(file_path)
        return {
            'redacted_path': redacted_path,
            'analysis': analysis,
            'file_type': 'excel'
        }
    
    elif ext == '.pptx':
        redacted_path, analysis = process_powerpoint(file_path)
        return {
            'redacted_path': redacted_path,
            'analysis': analysis,
            'file_type': 'powerpoint'
        }
    
    else:
        raise ValueError(f"Unsupported file type: {ext}")


def is_image_scenic(file_path: Path) -> bool:
    """
    Determine if an image is scenic (photo-like) or text-heavy (screenshot/document)
    
    Args:
        file_path: Path to image
    
    Returns:
        bool: True if scenic, False if text-heavy
    """
    try:
        img = cv2.imread(str(file_path))
        if img is None:
            return False
        
        # Quick OCR test to see if there's significant text
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        text = pytesseract.image_to_string(gray)
        
        # If more than 20 characters detected, it's probably text-heavy
        if len(text.strip()) > 20:
            return False
        
        return True
    except Exception as e:
        print(f"Error detecting image type: {e}")
        return False  # Default to text-heavy for safety


# --- Processing Functions ---
def process_scenic_image(file_path: Path):
    """Handles redaction and analysis for SCENIC images (non-text) using YOLO and LLaVA."""
    print(f"Processing scenic image: {file_path.name}")
    
    img = cv2.imread(str(file_path))
    if img is None:
        return None, "Error: Could not read image"
    
    yolo_model = get_yolo_model()
    if yolo_model is not None:
        results = yolo_model(img)[0]
        
        for box in results.boxes:
            x1, y1, x2, y2 = [int(i) for i in box.xyxy[0]]
            roi = img[y1:y2, x1:x2]
            if roi.size > 0:
                blurred_roi = cv2.GaussianBlur(roi, (51, 51), 0)
                img[y1:y2, x1:x2] = blurred_roi
    
    redacted_filename = f"{file_path.stem}_redacted_scenic.png"
    redacted_path = REDACTED_DIR / redacted_filename
    cv2.imwrite(str(redacted_path), img)
    
    # Try LLaVA analysis
    llava_model = get_llava_model()
    if llava_model is not None:
        print("Analyzing scenic image with LLaVA...")
        try:
            image_path_uri = file_path.resolve().as_uri()
            prompt = "Provide a detailed description of this image. What is happening? What objects are present? What is the context?"
            message = HumanMessage(
                content=[
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_path_uri}},
                ]
            )
            response = llava_model.invoke([message])
            analysis_text = response.content
        except Exception as e:
            analysis_text = f"Image processed but analysis failed: {e}"
    else:
        analysis_text = "Scenic image processed. YOLO redaction applied. (LLaVA not available for analysis)"
    
    return redacted_path, analysis_text


def process_text_image(file_path: Path, analyzer_engine: AnalyzerEngine):
    """
    Enhanced TEXT-HEAVY image processor with improved OCR and aggressive PII redaction
    """
    print(f"Performing enhanced OCR-based processing on {file_path.name}...")
    
    img = cv2.imread(str(file_path))
    if img is None:
        return None, "Error: Could not read image"
    
    # --- SPEED OPTIMIZATION: Resize large images before processing ---
    MAX_DIMENSION = 1800
    h, w, _ = img.shape
    if h > MAX_DIMENSION or w > MAX_DIMENSION:
        scale = MAX_DIMENSION / max(h, w)
        new_w, new_h = int(w * scale), int(h * scale)
        img = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
        print(f"Resized image from {w}x{h} to {new_w}x{new_h}")

    # Improve image quality for better OCR
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    # Apply adaptive thresholding to improve text clarity
    gray = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                  cv2.THRESH_BINARY, 11, 2)
    
    # Perform OCR with higher detail
    ocr_config = r'--oem 3 --psm 6'  # Use LSTM OCR engine, assume uniform text block
    ocr_data = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT, config=ocr_config)
    
    full_text_for_analysis = " ".join(word for word in ocr_data['text'] if word.strip())
    
    if not full_text_for_analysis:
        print("No text detected. Using VLM for description.")
        # If no text, use LLaVA for a general description
        _, analysis_text = process_scenic_image(file_path)
        # Since no PII was found, return the original image path instead of a redacted one
        return file_path, analysis_text
    
    # Comprehensive PII analysis with all entity types
    analyzer_results = analyzer_engine.analyze(
        text=full_text_for_analysis, 
        language='en',
        entities=[
            "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION",
            "CREDIT_CARD", "US_SSN", "US_DRIVER_LICENSE", "US_PASSPORT",
            "DATE_TIME", "NRP", "MEDICAL_LICENSE", "URL",
            "AWS_IDENTIFIER", "NETWORK_INFO", "FILE_PATH", "TIMESTAMP",
            "IDENTIFIER_NAME", "DURATION"
        ]
    )
    
    # If no PII is found, use VLM for a description instead of returning raw text
    if not analyzer_results:
        print("No PII found in text. Using VLM for a visual description.")
        _, analysis_text = process_scenic_image(file_path)
        # Return the original image path as no redaction is needed
        return file_path, analysis_text

    # Create character-level PII index
    pii_char_indices = set()
    for res in analyzer_results:
        for i in range(res.start, res.end):
            pii_char_indices.add(i)
    
    # Redact PII from image with larger blur radius for better coverage
    redacted_img = img.copy()
    current_char_index = 0
    
    for i, word in enumerate(ocr_data['text']):
        if word.strip():
            word_len = len(word)
            conf = int(ocr_data['conf'][i]) if ocr_data['conf'][i] != '-1' else 0
            
            # Check if any character of this word is PII
            is_pii = any((current_char_index + char_pos) in pii_char_indices 
                        for char_pos in range(word_len))
            
            # Also redact low-confidence text that might be PII
            if is_pii or (conf > 0 and conf < 60 and len(word) > 3):
                (x, y, w, h) = (ocr_data['left'][i], ocr_data['top'][i], 
                               ocr_data['width'][i], ocr_data['height'][i])
                
                # Add padding around text for better coverage
                padding = 5
                x = max(0, x - padding)
                y = max(0, y - padding)
                w = min(img.shape[1] - x, w + 2*padding)
                h = min(img.shape[0] - y, h + 2*padding)
                
                # Use heavier blur for complete redaction
                roi = redacted_img[y:y+h, x:x+w]
                if roi.size > 0:
                    # Option 1: Black box (most secure)
                    cv2.rectangle(redacted_img, (x, y), (x+w, y+h), (0, 0, 0), -1)
                    
                    # Option 2: Heavy blur (comment above, uncomment below)
                    # blurred_roi = cv2.GaussianBlur(roi, (51, 51), 50)
                    # redacted_img[y:y+h, x:x+w] = blurred_roi
            
            current_char_index += word_len + 1
    
    redacted_filename = f"{file_path.stem}_redacted_text.png"
    redacted_path = REDACTED_DIR / redacted_filename
    cv2.imwrite(str(redacted_path), redacted_img)
    
    return redacted_path, full_text_for_analysis


def process_pdf(file_path: Path):
    """Enhanced PDF processor with comprehensive PII redaction"""
    print(f"Processing PDF: {file_path.name}")
    
    full_text = ""
    
    try:
        with pdfplumber.open(file_path) as pdf:
            if not pdf.pages:
                return None, "Empty or invalid PDF."
            
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    full_text += page_text + "\n"
            
            # Check if PDF is scanned
            if len(full_text.strip()) < 100 * len(pdf.pages):
                print("PDF appears to be scanned. Processing all pages as images...")
                
                # Process each page as image
                all_redacted_pages = []
                all_text = []
                
                for page_num, page in enumerate(pdf.pages):
                    # --- SPEED OPTIMIZATION: Lower resolution for scanned PDFs ---
                    img = page.to_image(resolution=150).original # Was 300
                    temp_image_path = UPLOAD_DIR / f"{file_path.stem}_page{page_num+1}.png"
                    img.save(temp_image_path, format="PNG")
                    
                    # Process as text image
                    _, page_text = process_text_image(temp_image_path, get_analyzer())
                    all_text.append(page_text)
                    
                    # Load redacted image
                    redacted_img_path = REDACTED_DIR / f"{file_path.stem}_page{page_num+1}_redacted_text.png"
                    if redacted_img_path.exists():
                        all_redacted_pages.append(str(redacted_img_path))
                
                # Combine analysis
                combined_text = "\n".join(all_text)
                return f"Scanned PDF processed ({len(pdf.pages)} pages)", combined_text
            
            # Process text-based PDF with comprehensive entity detection
            else:
                analyzer = get_analyzer()
                anonymizer = get_anonymizer()
                
                analyzer_results = analyzer.analyze(
                    text=full_text, 
                    language='en',
                    entities=[
                        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION",
                        "CREDIT_CARD", "US_SSN", "DATE_TIME", "URL",
                        "AWS_IDENTIFIER", "NETWORK_INFO", "FILE_PATH", 
                        "TIMESTAMP", "IDENTIFIER_NAME", "DURATION"
                    ]
                )
                
                anonymized_result = anonymizer.anonymize(
                    text=full_text,
                    analyzer_results=analyzer_results
                )
                redacted_text = anonymized_result.text
                
                # Save redacted text
                redacted_filename = f"{file_path.stem}_redacted.txt"
                redacted_path = REDACTED_DIR / redacted_filename
                with open(redacted_path, 'w', encoding='utf-8') as f:
                    f.write(redacted_text)
                
                return redacted_path, redacted_text
    
    except Exception as e:
        print(f"Error processing PDF: {e}")
        return None, f"Error processing PDF: {e}"


def process_excel(file_path: Path):
    """Process Excel files with PII redaction"""
    print(f"Processing Excel: {file_path.name}")
    
    try:
        df = pd.read_excel(file_path)
        
        analyzer = get_analyzer()
        anonymizer = get_anonymizer()
        
        # Process each cell
        for col in df.columns:
            for idx, value in enumerate(df[col]):
                if pd.notna(value) and isinstance(value, str):
                    analyzer_results = analyzer.analyze(text=value, language='en')
                    if analyzer_results:
                        anonymized = anonymizer.anonymize(text=value, analyzer_results=analyzer_results)
                        df.at[idx, col] = anonymized.text
        
        # Save redacted Excel
        redacted_filename = f"{file_path.stem}_redacted.xlsx"
        redacted_path = REDACTED_DIR / redacted_filename
        df.to_excel(redacted_path, index=False)
        
        analysis = f"Excel file with {len(df)} rows and {len(df.columns)} columns. Columns: {', '.join(map(str, df.columns))}"
        
        return redacted_path, analysis
    
    except Exception as e:
        return None, f"Error processing Excel: {e}"


def process_powerpoint(file_path: Path):
    """Process PowerPoint files with PII redaction"""
    print(f"Processing PowerPoint: {file_path.name}")
    
    try:
        from pptx import Presentation
        
        prs = Presentation(str(file_path))
        analyzer = get_analyzer()
        anonymizer = get_anonymizer()
        
        all_text = []
        
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text") and shape.text:
                    text = shape.text
                    analyzer_results = analyzer.analyze(text=text, language='en')
                    if analyzer_results:
                        anonymized = anonymizer.anonymize(text=text, analyzer_results=analyzer_results)
                        shape.text = anonymized.text
                    all_text.append(shape.text)
        
        # Save redacted presentation
        redacted_filename = f"{file_path.stem}_redacted.pptx"
        redacted_path = REDACTED_DIR / redacted_filename
        prs.save(str(redacted_path))
        
        analysis = f"PowerPoint with {len(prs.slides)} slides. Content: {' '.join(all_text[:500])}"
        
        return redacted_path, analysis
    
    except Exception as e:
        return None, f"Error processing PowerPoint: {e}"


# --- Formatting Functions ---
def format_technical_analysis(analysis_text: str):
    """Uses LangChain to format technical data into the desired table structure."""
    print("Formatting final technical analysis...")
    
    llm = get_llm()
    if llm is None:
        return f"**File Description**: Analysis text\n\n**Key Findings**:\n{analysis_text[:500]}"
    
    template = """
    You are a helpful cybersecurity analyst AI. Based on the following text, provide a clear 'File Description' and detailed 'Key Findings'.
    For 'Key Findings', extract each rule or key item, its parameters, and explain its purpose in a bulleted list.
    
    Extracted Text:
    {analysis}
    
    Your Formatted Output:
    **File Description**: [Provide a concise, one-sentence summary of the content]
    
    **Key Findings**:
    * **Rule Name**: [Extract Rule 1 Name] - **Source**: [e.g., 0.0.0.0/0] - **Action**: [Allow/Deny] - **Protocol/Port**: [e.g., tcp:22] - **Purpose**: [Explain the purpose]
    * **Rule Name**: [Extract Rule 2 Name] - **Source**: [e.g., 10.128.0.0/9] - **Action**: [Allow/Deny] - **Protocol/Port**: [e.g., tcp:0-65535] - **Purpose**: [Explain the purpose]
    * (Continue for all items found)
    """
    
    try:
        prompt = PromptTemplate(template=template, input_variables=["analysis"])
        output_parser = StrOutputParser()
        chain = prompt | llm | output_parser
        formatted_result = chain.invoke({"analysis": analysis_text})
        return formatted_result
    except Exception as e:
        return f"Error formatting: {e}\n\nRaw analysis:\n{analysis_text}"


def format_generic_output(analysis_text: str):
    """Uses LangChain for generic formatting of descriptive text."""
    print("Formatting generic output...")
    
    llm = get_llm()
    if llm is None:
        return f"**File Description**: Processed file\n\n**Key Findings**:\n* {analysis_text[:200]}"
    
    template = """
    Based on the following analysis, generate a 'File Description' and 'Key Findings' in a structured format.
    The 'File Description' should be a concise, one-sentence summary.
    The 'Key Findings' should be a bulleted list of the most important insights.
    
    Analysis Text:
    {analysis}
    
    Formatted Output:
    **File Description**: [Your one-sentence description here]
    
    **Key Findings**:
    * [Finding 1]
    * [Finding 2]
    * [Finding 3]
    """
    
    try:
        prompt = PromptTemplate(template=template, input_variables=["analysis"])
        output_parser = StrOutputParser()
        chain = prompt | llm | output_parser
        formatted_result = chain.invoke({"analysis": analysis_text})
        return formatted_result
    except Exception as e:
        return f"Error formatting: {e}\n\nRaw analysis:\n{analysis_text}"


def format_final_output(analysis_text: str, is_technical: bool = False):
    """
    Wrapper function to format output based on content type.
    Automatically chooses between technical and generic formatting.
    
    Args:
        analysis_text: Raw analysis text to format
        is_technical: If True, uses technical formatting. If False, uses generic.
    
    Returns:
        str: Formatted output with File Description and Key Findings
    """
    if is_technical:
        # Check if text contains technical indicators
        technical_keywords = ['rule', 'policy', 'firewall', 'security group', 'arn:', 
                             'protocol', 'port', 'cidr', 'ingress', 'egress']
        
        text_lower = analysis_text.lower()
        if any(keyword in text_lower for keyword in technical_keywords):
            return format_technical_analysis(analysis_text)
    
    return format_generic_output(analysis_text)


# --- Alias for main.py compatibility ---
def redact_text_in_image(file_path: Path, analyzer_engine: AnalyzerEngine = None):
    """
    Alias function for backward compatibility with main.py
    This is the same as process_text_image()
    
    Args:
        file_path: Path to the image file
        analyzer_engine: Presidio analyzer (optional, will use default if None)
    
    Returns:
        tuple: (redacted_file_path, extracted_text)
    """
    if analyzer_engine is None:
        analyzer_engine = get_analyzer()
    
    return process_text_image(file_path, analyzer_engine)


# --- Create analyzer instance for direct export ---
analyzer = get_analyzer()


# --- Exported Functions for main.py ---
__all__ = [
    'process_file',
    'process_image',
    'process_pdf',
    'process_excel',
    'process_powerpoint',
    'process_scenic_image',
    'process_text_image',
    'redact_text_in_image',  # Added for main.py compatibility
    'format_technical_analysis',
    'format_generic_output',
    'format_final_output',
    'analyzer',  # Export analyzer instance
    'UPLOAD_DIR',
    'REDACTED_DIR',
    'MODEL_DIR'
]