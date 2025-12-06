#!/bin/bash
# Terrabridge Compliance Sensor Installation Script
# For Ubuntu/RHEL/CentOS Linux distributions

set -e

INSTALL_DIR="/opt/terrabridge"
CONFIG_DIR="/etc/terrabridge"
SERVICE_FILE="/etc/systemd/system/compliance-sensor.service"

echo "========================================"
echo "Terrabridge Compliance Sensor Installer"
echo "========================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Detect distro
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Unable to detect Linux distribution"
    exit 1
fi

echo "Detected distribution: $DISTRO"

# Install dependencies
echo ""
echo "[1/6] Installing system dependencies..."
case $DISTRO in
    ubuntu|debian)
        apt-get update
        apt-get install -y python3 python3-pip python3-venv auditd audispd-plugins
        ;;
    rhel|centos|fedora|rocky|almalinux)
        dnf install -y python3 python3-pip audit audit-libs
        ;;
    *)
        echo "Unsupported distribution: $DISTRO"
        exit 1
        ;;
esac

# Ensure auditd is running
echo ""
echo "[2/6] Configuring audit daemon..."
systemctl enable auditd
systemctl start auditd

# Create directories
echo ""
echo "[3/6] Creating installation directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR

# Create Python virtual environment
echo ""
echo "[4/6] Setting up Python environment..."
python3 -m venv $INSTALL_DIR/.venv
source $INSTALL_DIR/.venv/bin/activate

# Install the sensor package
echo ""
echo "[5/6] Installing Terrabridge sensor..."
pip install --upgrade pip
pip install terrabridge-mcp

# Create configuration file
echo ""
echo "[6/6] Creating configuration..."
if [ ! -f "$CONFIG_DIR/sensor.env" ]; then
    cat > $CONFIG_DIR/sensor.env << 'EOF'
# Terrabridge Compliance Sensor Configuration

# MCP Server URL (required)
MCP_SERVER_URL=http://localhost:8001

# Scan intervals in seconds
SENSOR_SCAN_INTERVAL=300
SENSOR_CRITICAL_INTERVAL=60

# Sensor identification
SENSOR_HOSTNAME=

# Optional API key for authentication
SENSOR_API_KEY=

# LLM settings (for AI analysis)
OPENAI_API_BASE=http://localhost:8000/v1
OPENAI_API_KEY=EMPTY
LLM_MODEL=ibm-granite/granite-4.0-h-micro
EOF
    echo "Created configuration at $CONFIG_DIR/sensor.env"
    echo "Please edit this file to set MCP_SERVER_URL"
else
    echo "Configuration already exists at $CONFIG_DIR/sensor.env"
fi

# Install systemd service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/compliance-sensor.service" ]; then
    cp "$SCRIPT_DIR/compliance-sensor.service" $SERVICE_FILE
else
    cat > $SERVICE_FILE << 'EOF'
[Unit]
Description=Terrabridge ISO 27001 Compliance Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=-/etc/terrabridge/sensor.env
WorkingDirectory=/opt/terrabridge
ExecStart=/opt/terrabridge/.venv/bin/compliance-sensor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=compliance-sensor

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
echo "Systemd service installed"

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Edit configuration: sudo nano $CONFIG_DIR/sensor.env"
echo "2. Set MCP_SERVER_URL to your MCP server address"
echo "3. Start the sensor: sudo systemctl start compliance-sensor"
echo "4. Enable on boot: sudo systemctl enable compliance-sensor"
echo "5. Check status: sudo systemctl status compliance-sensor"
echo "6. View logs: sudo journalctl -u compliance-sensor -f"
echo ""
echo "Manual test run: sudo /opt/terrabridge/.venv/bin/compliance-sensor --once"
echo ""

