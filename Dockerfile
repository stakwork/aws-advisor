# aws-advisor: the app, its built UI, and a Steampipe service with the AWS plugin and the Thrifty mod, in
# one image. Modelled on stakgraph-mcp's image (ghcr.io/stakwork, multi-arch, published on release).
#
#   docker build -t aws-advisor .
#   docker run -p 9034:9034 -v aws-advisor-data:/data -e API_TOKEN=... -e MCP_TOKEN=... -e CALLBACK_SECRET=... aws-advisor
#
# Steampipe refuses to run as root, so everything runs as the `advisor` user; /data holds the SQLite database,
# the Steampipe config (the connection the app writes) and the AWS files (~/.aws), all on one volume.

# ---- build the UI and check the server's types --------------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY ui/package.json ui/package-lock.json ./ui/
# `install`, not `ci`, for the UI: the lockfile was written on macOS and npm ci skips the optional native
# packages (lightningcss, tailwind oxide) of a different platform.
RUN npm ci && npm --prefix ui install --no-audit --no-fund
COPY . .
RUN npm run build

# ---- runtime -------------------------------------------------------------------------------------------------
FROM node:22-bookworm-slim
ARG STEAMPIPE_VERSION=latest
ARG POWERPIPE_VERSION=latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gosu tar && rm -rf /var/lib/apt/lists/* \
 && /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)" \
 && /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)" \
 && useradd --create-home --shell /bin/bash advisor

WORKDIR /usr/src/app
COPY --from=build /src/package.json /src/package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /src/src ./src
COPY --from=build /src/mod ./mod
COPY --from=build /src/tasks ./tasks
COPY --from=build /src/ui/dist ./ui/dist
COPY --from=build /src/README.md ./README.md
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && chown -R advisor:advisor /usr/src/app

# Steampipe's plugin and Powerpipe's mod dependencies are fetched at build time so a container starts offline-ready.
USER advisor
ENV HOME=/home/advisor
RUN steampipe plugin install aws --skip-config \
 && cd /usr/src/app/mod && powerpipe mod install
USER root

# One volume for everything that must survive a recreation: the database, the Steampipe connection the app
# writes, the AWS config and credentials files. The entrypoint links them into the advisor home.
VOLUME ["/data"]
ENV DATA_DIR=/data/advisor \
    STEAMPIPE_CONFIG_DIR=/data/steampipe/config \
    AWS_CONFIG_FILE=/data/aws/config \
    AWS_SHARED_CREDENTIALS_FILE=/data/aws/credentials \
    STEAMPIPE_DATABASE_URL=postgres://steampipe@127.0.0.1:9193/steampipe \
    POWERPIPE_MOD_DIR=/usr/src/app/mod \
    PORT=9034 \
    NODE_ENV=production
EXPOSE 9034
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "--import", "tsx", "src/index.ts"]
