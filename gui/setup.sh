#!/bin/bash
# Namestitveni skript grafičnega vmesnika NetSentinel IDS za Linux/Mac.
# Samodejno pripravi okolje Python in namesti odvisnosti.

echo ""
echo "========================================"
echo "NetSentinel IDS - GUI Setup"
echo "========================================"
echo ""

# Preveri, ali je Python nameščen.
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python 3.8+ using:"
    echo "  Ubuntu/Debian: sudo apt-get install python3 python3-pip python3-venv"
    echo "  Mac: brew install python3"
    exit 1
fi

echo "[1/4] Checking Python version..."
python3 --version

echo ""
echo "[2/4] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists - skipping"
else
    python3 -m venv venv
    echo "Virtual environment created"
fi

echo ""
echo "[3/4] Activating virtual environment..."
source venv/bin/activate

echo ""
echo "[4/4] Installing dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo ""
echo "========================================"
echo "Setup complete!"
echo "========================================"
echo ""
echo "To run the GUI dashboard:"
echo "  1. Make sure NetSentinel IDS C++ backend is running"
echo "     (should be listening on http://localhost:8080)"
echo "  2. Run: python main.py"
echo ""
echo "Or directly activate environment and run:"
echo "  source venv/bin/activate"
echo "  python main.py"
echo ""
