FROM python:alpine

RUN pip install --upgrade pip && pip install permit colorlog

COPY checker.py /checker.py

CMD ["python", "/checker.py"]
