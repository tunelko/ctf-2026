FROM sagemath/sagemath:latest
RUN sage -pip install pycryptodome
WORKDIR /app
COPY . /app
CMD ["sage", "solve.sage"]
