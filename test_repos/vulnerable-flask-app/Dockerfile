FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask psycopg2-binary

COPY app.py .

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "app", "run", "--host=0.0.0.0", "--port=5000"]
