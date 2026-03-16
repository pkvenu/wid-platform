FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY src/ ./src/
COPY keys/ ./keys/
# Shared modules (copied into service dir for Docker builds)
COPY shared/ ./shared/
EXPOSE 3000
CMD ["npm", "start"]
