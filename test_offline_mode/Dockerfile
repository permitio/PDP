FROM python:3.13-alpine3.23

RUN pip install --upgrade pip && pip install permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
