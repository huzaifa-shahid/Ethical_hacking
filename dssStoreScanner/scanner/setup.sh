#!/bin/bash

echo "[+] Setting up .DS_Store Scanner Environment..."

python3 -m venv ds_env
source ds_env/bin/activate

echo "[+] Upgrading pip..."
pip install --upgrade pip

echo "[+] Installing Python dependencies..."
pip install requests

if [ ! -d "dsstore" ]; then
    echo "[+] Cloning dsstore parser..."
    git clone https://github.com/lijiejie/dsstore.git
fi

cd dsstore || exit
pip install -r requirements.txt
cd ..

echo "[✓] Setup complete. To activate the environment, run: source ds_env/bin/activate"
