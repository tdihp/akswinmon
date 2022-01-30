FROM python:3-slim

WORKDIR /usr/src/app

COPY requirements.txt controller.py ./
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "controller.py"]
