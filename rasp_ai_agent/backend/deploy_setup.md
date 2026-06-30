# Server Deployment Setup Guide (Git Push-to-Deploy)

This guide shows you how to set up the server (`10.200.10.155`) so you can push your local backend code directly using `git push` and have it automatically build and start in Docker.

---

## 1. Setup on Remote Server (`10.200.10.155`)

Login to your server using SSH (e.g. user `soc`):
```bash
ssh soc@10.200.10.155
```

### A. Install Docker and Git (if not already installed)
Run the following commands:
```bash
# Update package list and install docker + git
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git

# Add your user to the docker group so you don't need sudo for docker commands
sudo usermod -aG docker $USER

# Log out and log back in for changes to take effect:
exit
ssh soc@10.200.10.155
```

### B. Create target deployment directory
Create the directory where your actual running code will reside:
```bash
mkdir -p ~/rasp_ai_agent
```

### C. Initialize Bare Git Repository
Initialize a bare Git repository. This repository will only store the git history and act as the destination for your `git push`.
```bash
mkdir -p ~/rasp_ai_agent.git
cd ~/rasp_ai_agent.git
git init --bare
```

### D. Setup Git `post-receive` Hook
Create the post-receive hook script. This script automatically runs whenever you push code to this repository.
```bash
nano hooks/post-receive
```

Paste the following content into the file:
```bash
#!/bin/bash
# Checkout the pushed code into the target running directory
TARGET="/home/soc/rasp_ai_agent"
GIT_DIR="/home/soc/rasp_ai_agent.git"

echo "=== Git push received: deploying code to $TARGET ==="
git --work-tree=$TARGET --git-dir=$GIT_DIR checkout -f

cd $TARGET

# Initialize .env if it doesn't exist
if [ ! -f .env ]; then
  echo "No .env found. Creating .env from .env.example..."
  cp .env.example .env
  echo "--> PLEASE EDIT $TARGET/.env with your production values!"
fi

echo "=== Rebuilding and starting Docker containers ==="
docker compose down
docker compose up -d --build

echo "=== Deployment completed successfully! ==="
```

Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).

Make the hook script executable:
```bash
chmod +x hooks/post-receive
```

---

## 2. Configure Host Ollama on Server

If you are running Ollama on the server host machine (outside Docker), you must configure it to listen on all interfaces so the backend Docker container can access it:

1. Edit the Ollama systemd service configuration:
   ```bash
   sudo systemctl edit ollama.service
   ```
2. Add the following lines to configure it to bind to `0.0.0.0`:
   ```ini
   [Service]
   Environment="OLLAMA_HOST=0.0.0.0"
   ```
3. Save, exit, and restart Ollama:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart ollama
   ```

---

## 3. Setup on Local Machine

Open terminal/cmd in your local `backend` directory `D:\DarshanProject\rasp_ai_agent\backend`.

### A. Initialize Git (if not already done)
```bash
git init
```

### B. Add Remote Server Reference
Add the remote destination (`server`) pointing to your bare git repo on `10.200.10.155`:
```bash
git remote add server ssh://soc@10.200.10.155/home/soc/rasp_ai_agent.git
```

### C. Commit Your Changes
Make sure all your changes are committed locally:
```bash
git add .
git commit -m "config: configure server port binding, host mapping, and git deploy hook"
```

### D. Push to Server
Push your branch (usually `main` or `master`) to the server:
```bash
git push server main
```

This will trigger the `post-receive` hook on the server, which checks out the code to `~/rasp_ai_agent`, runs the container, and starts your RASP AI backend at:
**`http://10.200.10.155:8001`**

---

## 4. Verification and URLs

Once deployed, you can access the dashboard and API at:
* **API Documentation (Swagger UI)**: `http://10.200.10.155:8001/docs`
* **Real-time Security Dashboard**: `http://10.200.10.155:8001/dashboard/`
* **Health Endpoint**: `http://10.200.10.155:8001/api/v1/security/health`
