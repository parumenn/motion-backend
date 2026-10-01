FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build || npx tsc

EXPOSE 3000

CMD ["npx", "tsx", "src/server.ts"]