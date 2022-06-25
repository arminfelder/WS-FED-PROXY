FROM node:lts-bullseye-slim


RUN useradd appuser

COPY . /app

WORKDIR /app

RUN npm install ci

RUN chown -R node /app

CMD npm start
