#!/bin/bash
# Setup pre-commit hook for the SDLC demo project
# Run: bash scripts/setup-hooks.sh

set -e

HOOK_PATH=".git/hooks/pre-commit"

echo "Installing pre-commit agent hook..."

cat > "$HOOK_PATH" << 'EOF'
#!/bin/bash
# Pre-commit hook - runs the pre-commit agent
echo "🔍 Running pre-commit agent..."
python3 agents/precommit-agent.py

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Pre-commit agent BLOCKED the commit."
    echo "   Fix the issues above and try again."
    echo "   To bypass (not recommended): git commit --no-verify"
    exit 1
fi

echo "✅ Pre-commit checks passed"
EOF

chmod +x "$HOOK_PATH"
echo "✅ Pre-commit hook installed at $HOOK_PATH"
echo ""
echo "The agent will now run automatically before each commit."
echo "To bypass in emergencies: git commit --no-verify"
