FROM python:3.9-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment variables will be provided at runtime
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=5000

# Expose the port
EXPOSE 5000

# Start with gunicorn - specify the module and application variable
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:application"]