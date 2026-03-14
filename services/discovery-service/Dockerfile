FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --production

# Copy source code
ARG CACHEBUST=1
COPY . .

# Shared module: agent-card-signer (placed at /shared/ to match require paths)
COPY agent-card-signer.js /shared/agent-card-signer.js

EXPOSE 3003

CMD ["node", "src/index.js"]

