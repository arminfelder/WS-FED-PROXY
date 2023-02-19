FROM node:lts-bullseye-slim


RUN useradd appuser

COPY . /app

WORKDIR /app

RUN npm ci

RUN chown -R node /app

CMD npm start
