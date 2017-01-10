# Needs to be python 3.5 due to some cert issues that
# were showing up with eventlet + oauth2 flow
FROM python:3.5
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ./app.py
