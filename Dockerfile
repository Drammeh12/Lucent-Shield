# Lucent Shield — web dashboard, for Bash Cloud (or any Docker host).
FROM node:22-slim

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# Data (your protected assets + last scans) persists on a mounted disk.
ENV LUCENT_DATA_DIR=/data
ENV PORT=4600
EXPOSE 4600

# Set LUCENT_PASSWORD in the environment to require a login.
CMD ["npm", "start"]
