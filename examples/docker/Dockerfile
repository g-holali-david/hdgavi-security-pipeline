# Example Dockerfile — intentionally includes some issues for scanning
FROM python:3.12-slim

LABEL maintainer="g-holali-david"

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root user
RUN useradd -m appuser
USER appuser

EXPOSE 8000

CMD ["python", "app.py"]
