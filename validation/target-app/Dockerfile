FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && chown -R node:node /app

COPY server.js ./
RUN chown node:node server.js

USER node

EXPOSE 3000

CMD ["node", "server.js"]
