#!/bin/bash
# Safe launcher for vulnerable applications

echo "================================================"
echo "⚠️  SECURITY WARNING - VULNERABLE APPLICATION ⚠️"
echo "================================================"
echo ""
echo "This application is INTENTIONALLY VULNERABLE!"
echo ""
echo "Safety checklist:"
echo "[ ] Running in isolated VM/container?"
echo "[ ] Network is isolated/firewalled?"
echo "[ ] VM snapshot taken?"
echo "[ ] No production data present?"
echo ""
read -p "Type 'I UNDERSTAND THE RISKS' to continue: " confirmation

if [ "$confirmation" != "I UNDERSTAND THE RISKS" ]; then
    echo "Aborted for safety. Please review SECURITY.md"
    exit 1
fi

echo ""
echo "Starting vulnerable app on 127.0.0.1 ONLY..."
echo "Press Ctrl+C to stop"
echo ""

# Force localhost binding
docker run --rm -p 127.0.0.1:5000:5000 --name vuln-app-safe vulnerable-app
