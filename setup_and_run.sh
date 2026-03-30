#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  AWS Cloud Management Suite — Universal Run Script
#  Modules: Inventory | Cost Optimization | Security Audit | Monthly
#  Usage:  bash setup_and_run.sh
# ─────────────────────────────────────────────────────────────────

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/venv"
PY=""

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AWS Cloud Management Suite — Shellkode"
echo "  Modules: Inventory | Cost | Security Audit | Monthly"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Find Python 3 ──────────────────────────────────────
echo "[ 1/6 ] Locating Python 3..."
for cmd in python3 python3.12 python3.11 python3.10 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null)
        if [ "$VER" = "3" ]; then
            PY=$(command -v "$cmd")
            break
        fi
    fi
done

if [ -z "$PY" ]; then
    echo "  ❌ Python 3 not found. Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-venv python3-pip python3-full
    PY=$(command -v python3)
fi
echo "  ✅ Python: $PY ($($PY --version 2>&1))"

# ── Step 2: Ensure python3-venv is available ───────────────────
echo ""
echo "[ 2/6 ] Checking venv support..."
if ! "$PY" -m venv --help &>/dev/null 2>&1; then
    echo "  📦 Installing python3-venv..."
    sudo apt-get install -y python3-venv python3-full 2>/dev/null || \
    sudo apt-get install -y "python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')-venv" 2>/dev/null || true
fi
echo "  ✅ venv available"

# ── Step 3: Create or reuse virtual environment ───────────────
echo ""
echo "[ 3/6 ] Setting up virtual environment..."
if [ ! -d "$VENV" ]; then
    echo "  🔧 Creating venv at $VENV ..."
    "$PY" -m venv "$VENV"
    echo "  ✅ Virtual environment created"
else
    echo "  ✅ Using existing venv: $VENV"
fi

VPYTHON="$VENV/bin/python"
VPIP="$VENV/bin/pip"

# ── Step 4: Install core packages ────────────────────────────
echo ""
echo "[ 4/6 ] Installing core packages (flask, boto3, pandas)..."
"$VPIP" install --upgrade pip --quiet
"$VPIP" install flask flask-cors boto3 pandas numpy xlsxwriter python-docx --quiet
echo "  ✅ Core packages installed"

# ── Step 5: Install Prowler (Security Audit) ─────────────────
echo ""
echo "[ 5/6 ] Installing Prowler (Security Audit module)..."
if "$VPIP" show prowler &>/dev/null 2>&1; then
    PROWLER_VER=$("$VPIP" show prowler | grep Version | awk '{print $2}')
    echo "  ✅ Prowler already installed (v$PROWLER_VER)"
else
    echo "  📥 Installing Prowler — this may take 1-2 minutes..."
    if "$VPIP" install prowler --quiet 2>&1; then
        PROWLER_VER=$("$VPIP" show prowler 2>/dev/null | grep Version | awk '{print $2}')
        echo "  ✅ Prowler installed (v$PROWLER_VER)"
    else
        echo "  ⚠️  Prowler install failed (non-fatal)"
        echo "  ℹ️  Security Audit will auto-retry when you click 'Run Prowler Scan'"
        echo "  ℹ️  Manual install: source venv/bin/activate && pip install prowler"
    fi
fi

# ── Step 6: Check required files ─────────────────────────────
echo ""
echo "[ 6/6 ] Verifying package files..."
SERVER="$DIR/aws_inventory_server.py"
FRONTEND="$DIR/frontend.html"

MISSING=0
for f in "$SERVER" "$FRONTEND"; do
    if [ ! -f "$f" ]; then
        echo "  ❌ Missing: $f"
        MISSING=1
    else
        echo "  ✅ Found: $(basename $f)"
    fi
done

if [ "$MISSING" = "1" ]; then
    echo ""
    echo "  ❌ Required files missing. Make sure these are in: $DIR"
    echo "     - aws_inventory_server.py"
    echo "     - frontend.html"
    exit 1
fi

# ── Launch ────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ All ready! Starting server..."
echo ""
echo "  🌐 Open in browser:  http://localhost:8080"
echo ""
echo "  📦 Inventory        — 200+ AWS services grouped"
echo "  💰 Cost Optimization — 3-month cost + savings"
echo "  🔒 Security Audit   — Prowler scan (auto-installed)"
echo "  📊 Monthly Report   — Billing diff + utilization"
echo ""
echo "  Press Ctrl+C to stop the server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

"$VPYTHON" "$SERVER"
