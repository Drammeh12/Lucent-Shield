# Lucent Shield — web dashboard, for Bash Cloud (or any Docker host).
FROM node:22-slim

# git is needed for white-box scanning of GitHub/GitLab repository URLs.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# Run as the unprivileged "node" user, never root. /data must be writable by it.
RUN mkdir -p /data && chown -R node:node /data /app
USER node

# Data (your protected assets + last scans) persists on a mounted disk.
ENV LUCENT_DATA_DIR=/data
ENV PORT=4600
EXPOSE 4600

# People create accounts in the app. Set LUCENT_ADMIN_EMAIL + LUCENT_ADMIN_PASSWORD for the admin account.
# Optional: LUCENT_GITHUB_TOKEN so the admin can scan private GitHub repos (white box).
# Optional: LUCENT_ALERT_WEBHOOK to mirror alerts to Slack/Discord.
CMD ["npm", "start"]
