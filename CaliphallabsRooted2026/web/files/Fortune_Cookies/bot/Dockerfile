FROM mcr.microsoft.com/playwright/python:v1.40.0-focal

WORKDIR /bot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install

COPY bot.py .

CMD ["python", "bot.py"]
