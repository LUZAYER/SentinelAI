FROM python:3.13-slim

WORKDIR /app

# Install system dependencies for OpenCV and other detectors
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    file \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data
RUN python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab'); nltk.download('stopwords')"

# Copy application code
WORKDIR /
COPY . /backend
ENV PYTHONPATH=/:/backend

WORKDIR /backend

# Expose port
EXPOSE 8000

# Start server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
