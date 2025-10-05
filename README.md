# File Cleansing and Analysis AI Pipeline

A sophisticated AI-powered system for automatically detecting, redacting, and analyzing sensitive information in various file formats including images, PDFs, Excel files, and PowerPoint presentations.

## 🚀 Overview

This pipeline combines multiple AI models and computer vision techniques to:
- **Detect and redact PII (Personally Identifiable Information)** from documents
- **Analyze file content** using advanced language models
- **Generate professional reports** with structured findings
- **Handle multiple file formats** with specialized processing pipelines

## 🏗️ Pipeline Architecture

### Core Components

1. **Multi-Modal AI Detection System**
   - **LLaVA (Large Language and Vision Assistant)**: Analyzes images to determine content type (scenic vs text-heavy)
   - **YOLO Object Detection**: Identifies and redacts objects/people in scenic images
   - **Tesseract OCR**: Extracts text from images with high accuracy
   - **Presidio Analyzer**: Advanced PII detection with custom entity recognition

2. **Intelligent File Processing**
   - **Smart Content Classification**: Automatically determines optimal processing pipeline
   - **Adaptive Processing**: Different strategies for screenshots, documents, and scenic images
   - **Multi-Format Support**: Images, PDFs, Excel, PowerPoint files

3. **Professional Output Generation**
   - **LangChain Integration**: Formats raw analysis into structured reports
   - **Technical Analysis**: Specialized formatting for firewall rules, policies, and technical documents
   - **Clean Web Interface**: Professional black-and-white themed frontend

## 📁 Project Structure

```
├── best.pt                    # YOLOv8 model weights for object detection
├── main.py                   # FastAPI backend server
├── pipeline.py               # Core processing pipeline
├── requirements.txt          # Python dependencies
├── frontend/                 # Web interface
│   ├── index.html           # Main HTML template
│   ├── script.js            # Frontend JavaScript logic
│   └── style.css            # Professional styling
├── models/                   # AI model files
│   ├── ggml-model-q5_k.gguf        # LLaVA vision model
│   ├── mistral-7b-instruct-v0.2.Q5_K_M.gguf  # Language model
│   └── mmproj-model-f16.gguf       # Vision projection model
├── redacted_files/          # Output directory for processed files
└── uploads/                 # Temporary upload directory
```

## 🔄 Processing Pipeline Flow

### 1. File Upload & Classification
```
User Upload → File Type Detection → Route to Specialized Processor
```

### 2. Image Processing Pipeline
```
Image Input → LLaVA Content Analysis → Decision Tree:
├── Text-Heavy/Screenshot → OCR + PII Detection + Redaction
├── Scenic Image → YOLO Object Detection + Redaction
└── Technical Document → Enhanced OCR + Technical Analysis
```

### 3. Document Processing Pipeline
```
PDF/Excel/PPT → Text Extraction → PII Analysis → Content Redaction → Report Generation
```

### 4. Output Generation
```
Raw Analysis → LangChain Formatting → Structured Report → Download Links
```

## 🛡️ Security Features

### PII Detection & Redaction
- **Comprehensive Entity Recognition**: Names, emails, phone numbers, SSNs, credit cards, addresses, AWS identifiers, network information
- **Multi-Layer Detection**: Combines rule-based patterns with ML models
- **Visual Redaction**: Black boxes or blur effects for complete information removal
- **Low-Confidence Text Handling**: Redacts uncertain OCR results that might contain PII

### Custom Entity Patterns
```python
# AWS-specific identifiers
"AWS_IDENTIFIER": r"AKIA[0-9A-Z]{16}|aws:[a-zA-Z0-9-]+:[a-zA-Z0-9-]+"

# Network information
"NETWORK_INFO": r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"

# File paths and timestamps
"FILE_PATH": r"[A-Za-z]:\\[\w\s\\.-]+|/[\w\s/.-]+"
"TIMESTAMP": r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
```

## 🎯 Key Strengths

### 1. **Intelligent Content Understanding**
- Uses LLaVA to understand image context before processing
- Adapts processing strategy based on content type
- Handles both text-heavy and scenic images appropriately

### 2. **Multi-Modal AI Integration**
- Combines computer vision, NLP, and OCR technologies
- Each component specialized for specific tasks
- Fallback mechanisms ensure reliability

### 3. **Professional Output Quality**
- LangChain-powered report generation
- Structured formatting for technical documents
- Professional web interface with gradient themes

### 4. **Performance Optimizations**
- Image resizing for faster processing
- Lazy model loading to reduce memory usage
- Efficient OCR configuration for different content types

### 5. **Comprehensive File Support**
- Images (PNG, JPG, JPEG, GIF, BMP, TIFF)
- PDF documents (both text-based and scanned)
- Microsoft Office files (Excel, PowerPoint)
- Automatic format detection and routing

## ⚠️ Potential Security Threats & Considerations

### 1. **False Negatives in PII Detection**
- **Risk**: Some PII might not be detected by the analyzer
- **Mitigation**: Multiple detection layers, conservative redaction of low-confidence text
- **Recommendation**: Manual review for highly sensitive documents

### 2. **Model Dependencies**
- **Risk**: Large AI models require significant computational resources
- **Threat**: Model files could be tampered with if not properly secured
- **Mitigation**: Verify model checksums, use trusted model sources

### 3. **OCR Accuracy Limitations**
- **Risk**: Poor image quality might lead to missed text
- **Mitigation**: Image preprocessing, multiple OCR strategies
- **Recommendation**: Use high-quality source images when possible

### 4. **Memory and Processing Intensive**
- **Risk**: Large files might cause system resource exhaustion
- **Mitigation**: File size limits, image resizing, timeout configurations
- **Recommendation**: Deploy on adequately resourced infrastructure

### 5. **Data Privacy During Processing**
- **Risk**: Sensitive data temporarily stored during processing
- **Mitigation**: Automatic cleanup of temporary files, in-memory processing where possible
- **Recommendation**: Deploy in secure, isolated environments

## 🚀 Getting Started

### Prerequisites
```bash
Python 3.8+
Tesseract OCR
CUDA (optional, for GPU acceleration)
```

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd file-cleansing-ai

# Install dependencies
pip install -r requirements.txt

# Download required models (place in models/ directory)
# - mistral-7b-instruct-v0.2.Q5_K_M.gguf
# - ggml-model-q5_k.gguf
# - mmproj-model-f16.gguf

# Start the server
uvicorn main:app --reload
```

### Access the Application
Open your browser to `http://127.0.0.1:8000`

## 📊 Example Output

```json
{
  "original_filename": "policy_document.png",
  "redacted_file_path": "redacted_files/policy_document_redacted_text.png",
  "analysis": "
    **File Description**: This document represents an AWS Identity and Access Management (IAM) policy that grants read access to Amazon S3 resources.
    
    **Key Findings**:
    * **Rule 1 - Source: X - Action: Allow - Protocol/Port: s3:Get* - Purpose**: Grants read-only access to the specified Amazon S3 resource.
    * **Rule 1 - Source: X - Action: Allow - Protocol/Port: s3:List - Purpose**: Allows listing of objects within the specified Amazon S3 resource.
    * **Rule 1 - Effect**: Allows all actions mentioned in this rule to be performed on the specified resource with read-only access."
}
```

## 🔧 Configuration Options

### Model Configuration
- Adjust OCR settings in [`pipeline.py`](pipeline.py)
- Modify PII detection entities
- Configure LLaVA and LLM model parameters

### Security Settings
- Customize redaction methods (blur vs black boxes)
- Adjust confidence thresholds for PII detection
- Configure file size and processing limits

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚡ Performance Notes

- **Image Processing**: ~2-5 seconds per image
- **PDF Processing**: ~1-3 seconds per page
- **Memory Usage**: ~2-4GB with all models loaded
- **GPU Acceleration**: Supported for YOLO and LLaVA models

---

**Note**: This system is designed for professional document processing with security in mind. Always verify output quality and implement additional security measures for highly sensitive environments.