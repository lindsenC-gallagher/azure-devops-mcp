# Azure DevOps MCP Server — Gallagher fork
#
# Runs the MCP server over stdio, so consumers can use it without cloning the
# repo or running `npm install`:
#
#   docker run -i --rm -e ADO_PAT=<pat> ghcr.io/lindsenc-gallagher/azure-devops-mcp \
#     https://ado.company.local/tfs/DefaultCollection --authentication pat
#
# The optional native `kerberos` module is deliberately left out, so
# `--authentication wia` is not available in the image. Windows Integrated Auth
# needs the caller's own Kerberos ticket, which a container does not have. Use a
# local Node install for WIA (see docs/FORK-ONPREM-WIA.md).

FROM node:24-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
# --ignore-scripts skips the `prepare` hook, which runs husky and needs a git checkout.
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

FROM node:24-alpine AS runtime

ENV NODE_ENV=production

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional --ignore-scripts && npm cache clean --force

COPY --from=builder /app/dist ./dist

USER node

ENTRYPOINT ["node", "/app/dist/index.js"]
