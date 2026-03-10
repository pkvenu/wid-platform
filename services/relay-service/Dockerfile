FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY src/ src/
EXPOSE 3005
USER node
CMD ["node", "src/index.js"]
