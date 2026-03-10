FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --production

# Copy source code
ARG CACHEBUST=1
COPY . .

EXPOSE 3003

CMD ["node", "src/index.js"]

