FROM python:3.11-slim

RUN pip install --no-cache-dir pycryptodome

WORKDIR /app
COPY server.py /app/server.py
COPY flag.txt /app/flag.txt

ENV HOST=0.0.0.0
ENV PORT=1337

EXPOSE 1337
CMD ["python", "-u", "server.py"]
