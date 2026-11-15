FROM node:lts-trixie-slim AS builder

COPY . /app

WORKDIR /app

RUN npm ci --ignore-scripts

RUN npm test

RUN npm prune --omit=dev --ignore-scripts

FROM gcr.io/distroless/nodejs24-debian13:nonroot

COPY --from=builder /app /app

WORKDIR /app

# Without this, app.js skips its production checks and Express compiles each view again for each request.
# For a local stack with http URLs, set NODE_ENV=development at run time.
ENV NODE_ENV=production

USER 1000

CMD ["--permission", "--allow-fs-read=/app", "--allow-fs-read=/nodejs", "./bin/www"]
