FROM python:3.11-slim

# Install tshark (for pyshark)
RUN apt-get update && apt-get install -y tshark && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your project files
COPY . .

# Create output folder for reports (linked to SOC-Container volume)
RUN mkdir /out

# Run detection tool by default
CMD ["python", "detection.py"]
