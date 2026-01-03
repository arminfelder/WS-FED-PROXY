FROM node:lts-bullseye-slim AS builder

COPY . /app

WORKDIR /app

RUN npm ci

FROM gcr.io/distroless/nodejs24-debian13:nonroot

COPY --from=builder /app /app

WORKDIR /app

USER 1000

CMD ["./bin/www"]
