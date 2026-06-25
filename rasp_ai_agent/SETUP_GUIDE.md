# RASP Shield — Setup Guide for Beginners
# Complete step-by-step from zero to deployed

## Prerequisites — Install These First (Windows)

### 1. Install Git for Windows
Download from: https://git-scm.com/download/win
During install: choose "Git Bash" option
Verify: open Git Bash and type: git --version

### 2. Install Docker Desktop for Windows
Download from: https://www.docker.com/products/docker-desktop
Requirements: Windows 10/11 with WSL2
After install: start Docker Desktop, wait for green icon
Verify: docker --version && docker compose version

### 3. Install Flutter (for local development)
Download from: https://docs.flutter.dev/get-started/install
Add flutter/bin to PATH
Verify: flutter doctor

---

## Step 1 — Clone Repository

Open Git Bash:

  git clone https://github.com/DarshanOP18/\
Runtime-Application-and-Self-Protection---App-SDK.git
  cd Runtime-Application-and-Self-Protection---App-SDK

---

## Step 2 — Setup AI Agent Backend

  cd rasp_ai_agent

  # Copy environment template
  cp .env.example .env

  # Edit .env with your values (use Notepad or VS Code)
  notepad .env

  # Start development server
  make dev

  # Verify it works (open new Git Bash window)
  curl http://127.0.0.1:8001/api/v1/security/health

  # Expected response:
  # {"status":"healthy",...}

---

## Step 3 — Build Flutter APK

  cd ../rasp_app

  # Make script executable (Git Bash)
  chmod +x deploy/build_apk.sh

  # Build release APK
  ./deploy/build_apk.sh release

  # APK will be at:
  # rasp_app/build/outputs/rasp_shield_release_[timestamp].apk

---

## Step 4 — Push to GitHub

  # Stage all files
  git add .

  # Commit
  git commit -m "feat: add Docker and CI/CD pipeline"

  # Push (you will be prompted for GitHub credentials)
  # Username: DarshanOP18
  # Password: use your NEW GitHub token (not the old one)
  git push origin main

  # After push → go to GitHub Actions tab
  # You will see CI pipeline running automatically

---

## Step 5 — Add GitHub Secrets

Go to your repository on GitHub:
  Settings → Secrets and variables → Actions
  → New repository secret

Add each secret from this list:

  Secret Name              | Where to get the value
  ─────────────────────────────────────────────────
  DOCKER_USERNAME          | Your Docker Hub username
  DOCKER_PASSWORD          | Docker Hub → Account Settings
                           | → Security → New Access Token
  DEPLOY_HOST              | Office server IP address
                           | (ask your IT team)
  DEPLOY_USER              | SSH username on server
                           | (usually your login name)
  DEPLOY_SSH_KEY           | Run in Git Bash:
                           | cat ~/.ssh/id_rsa
                           | Copy entire output
  DEPLOY_SSH_PORT          | Usually 22 (default SSH port)
  ANDROID_KEYSTORE_BASE64  | See Step 6 below
  KEY_ALIAS                | Alias you chose for keystore
  KEY_PASSWORD             | Key password you set
  STORE_PASSWORD           | Store password you set

---

## Step 6 — Create Android Signing Keystore (One Time)

Run in Git Bash:

  keytool -genkey -v \
    -keystore rasp_keystore.jks \
    -alias rasp_shield_key \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000

  # When prompted:
  # Enter keystore password: (choose a strong password)
  # Re-enter password: (same password)
  # What is your first and last name? Your name
  # What is your organizational unit? Security
  # What is your organization? Your company
  # What is your city? Your city
  # What is your state? Your state
  # What is your country code? IN
  # Confirm with: yes

  # Encode for GitHub Secrets:
  # Windows PowerShell:
  [Convert]::ToBase64String(
    [IO.File]::ReadAllBytes(
      "$PWD\rasp_keystore.jks"))

  # Copy the output → paste as ANDROID_KEYSTORE_BASE64

  # KEEP rasp_keystore.jks SAFE — back it up!
  # NEVER commit it to git

---

## Step 7 — Deploy to Office Server (Linux)

SSH into the office server. Ask your IT team for:
  - Server IP address
  - Your SSH username
  - SSH port number

Then run these commands ON THE OFFICE SERVER:

  # Install Docker (requires IT approval for sudo)
  sudo apt-get update
  sudo apt-get install -y docker.io docker-compose-plugin

  # Add yourself to docker group
  sudo usermod -aG docker $USER

  # IMPORTANT: logout and login again for group to apply
  exit
  # SSH back in

  # Clone the project
  git clone https://github.com/DarshanOP18/\
Runtime-Application-and-Self-Protection---App-SDK.git
  cd Runtime-Application-and-Self-Protection---App-SDK/\
rasp_ai_agent

  # Setup environment
  cp .env.example .env
  nano .env    # fill in real values

  # Start production server
  make prod

  # Verify
  curl http://127.0.0.1:8001/api/v1/security/health

---

## Step 8 — Verify CI/CD Is Working

After pushing to GitHub:

  Push to feature branch → CI runs (analyze, test, build)
  Open Pull Request → CI must pass to merge
  Merge to main → CD runs (builds image, pushes to
                   Docker Hub, deploys to office server)

Watch it here:
  https://github.com/DarshanOP18/
  Runtime-Application-and-Self-Protection---App-SDK/actions

---

## Troubleshooting

Problem: Port 8001 already in use
Solution:
  # Find what is using it
  sudo lsof -i :8001
  # Kill that process
  sudo kill -9 <PID>

Problem: Docker permission denied
Solution:
  sudo usermod -aG docker $USER
  # Logout and login again

Problem: Flutter build runs out of memory
Solution:
  Open Docker Desktop → Settings → Resources
  Increase RAM to 6GB minimum

Problem: Ollama not connecting from Docker
Solution:
  # Check Ollama is running
  ollama serve
  # The .env should have:
  OLLAMA_BASE_URL=http://172.17.0.1:11434
  # 172.17.0.1 is the host machine from inside Docker

Problem: CI fails on lint
Solution:
  # Run locally first to see errors
  cd rasp_ai_agent
  pip install black isort flake8
  black app/ tests/
  isort app/ tests/
  flake8 app/ tests/ --max-line-length=100
