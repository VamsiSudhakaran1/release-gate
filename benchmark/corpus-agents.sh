#!/usr/bin/env bash
# Clone the deployed-agent dogfood corpus (see corpus-agents.md), then scan it:
#   ./benchmark/corpus-agents.sh /tmp/agents && release-gate audit /tmp/agents/<repo>
REPOS="
All-Hands-AI/OpenHands
princeton-nlp/SWE-agent
Aider-AI/aider
Codium-ai/pr-agent
potpie-ai/potpie
browser-use/browser-use
Skyvern-AI/skyvern
danny-avila/LibreChat
open-webui/open-webui
langgenius/dify
infiniflow/ragflow
QuivrHQ/quivr
modelcontextprotocol/servers
stitionai/devika
OpenInterpreter/open-interpreter
AntonOsika/gpt-engineer
e2b-dev/fragments
Upsonic/Upsonic
block/goose
frdel/agent-zero
"
for r in $REPOS; do
  n=$(echo "$r" | tr '/' '__')
  [ -d "$DEST/$n" ] && { echo "SKIP $r"; continue; }
  if timeout 240 git clone --depth 1 --quiet "https://github.com/$r" "$DEST/$n" 2>/dev/null; then
    echo "OK   $r"
  else
    echo "FAIL $r"; rm -rf "$DEST/$n"
  fi
done
echo "CLONE_DONE"
