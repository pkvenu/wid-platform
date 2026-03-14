FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY src/ ./src/
COPY keys/ ./keys/
# Shared module: agent-card-signer (placed at /shared/ to match require paths)
COPY agent-card-signer.js /shared/agent-card-signer.js
EXPOSE 3000
CMD ["npm", "start"]
