# Dockerfile
FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Exposes the port that the application will use
EXPOSE 5000

# Sets the environment variables
ENV DEBUG=False
ENV HOST=0.0.0.0
ENV PORT=5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app.main:app"]
