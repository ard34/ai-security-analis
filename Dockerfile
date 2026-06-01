FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY core ./core
COPY modules ./modules
COPY reporting ./reporting
COPY storage ./storage
COPY ui ./ui
COPY cli.py README.md ./

RUN mkdir -p data reports exports logs

EXPOSE 8501

CMD ["streamlit", "run", "app/dashboard.py", "--server.address=0.0.0.0"]
