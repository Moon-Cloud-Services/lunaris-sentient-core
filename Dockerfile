# Use an official Python base image
FROM python:3.8-slim-buster

# Sets the working directory in the container
WORKDIR /app

# Copies the requirements files to the working directory
COPY requirements.txt .

# Installs the project's dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copies the project code to the working directory
COPY . .

# Exposes the port that the application will use
EXPOSE 5000

# Sets the environment variables
ENV DEBUG=False
ENV HOST=0.0.0.0
ENV PORT=5000

# Command to run the application
CMD ["python", "app/main.py"]
