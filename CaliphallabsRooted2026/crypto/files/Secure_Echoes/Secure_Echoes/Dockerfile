FROM node:18-slim

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --production

COPY . .

RUN sqlite3 users.db < init.sql

EXPOSE 3000

CMD [ "node", "app.js" ]
