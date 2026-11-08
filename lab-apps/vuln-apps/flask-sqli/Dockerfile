FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Listen on all interfaces *inside* the container only; publish with -p 127.0.0.1:5000:5000
ENV HOST=0.0.0.0
EXPOSE 5000

# Run as non-root for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

CMD ["python", "app.py"]
