# Use a lightweight Python base image
FROM python:3.9-slim

# 1. Install System Tools (CURL is critical for healthcheck)
# We also add 'gcc' because some Python libraries need it to build.
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 2. Set up the working directory
WORKDIR /app

# 3. Copy requirements and install Python libraries
COPY requirements.txt .
# We explicitly install gunicorn here to be safe
RUN pip install --no-cache-dir -r requirements.txt && pip install gunicorn

# 4. Copy the rest of your application code
COPY . .

# 5. Define the "Start Command" (Using Gunicorn for Production)
# -w 4: Use 4 workers (like you had before)
# -b 0.0.0.0:5000: Listen on Port 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "main:app"]
