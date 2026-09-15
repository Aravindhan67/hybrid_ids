FROM python:3.10-slim

WORKDIR /app

# Copy the requirements file
COPY backend/requirements.txt ./backend/

# Install the necessary packages
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy both backend and ml_pipeline folders
COPY backend/ ./backend/
COPY ml_pipeline/ ./ml_pipeline/

# Set working directory to backend where main.py is located
WORKDIR /app/backend

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
