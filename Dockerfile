FROM python:3.9-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src /app/src
COPY config /app/config
COPY data /app/data
COPY reports /app/reports

CMD ["python", "src/deepphish.py"]
