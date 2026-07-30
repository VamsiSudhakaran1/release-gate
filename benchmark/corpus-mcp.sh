#!/usr/bin/env bash
# Clone the MCP-server dogfood corpus (see corpus-agents.md).
#   ./benchmark/corpus-mcp.sh /tmp/mcp
DEST="$1"; mkdir -p "$DEST"
REPOS="
0x4m4/hexstrike-ai
CursorTouch/Windows-MCP
agent-infra/sandbox
0xSteph/pentest-ai
bethington/ghidra-mcp
taylorwilsdon/google_workspace_mcp
homeassistant-ai/ha-mcp
atilaahmettaner/tradingview-mcp
knowsuchagency/mcp2cli
aipotheosis-labs/aci
awslabs/mcp
sooperset/mcp-atlassian
haris-musa/excel-mcp-server
stickerdaniel/linkedin-mcp-server
MarkusPfundstein/mcp-obsidian
blazickjp/arxiv-mcp-server
elevenlabs/elevenlabs-mcp
MiniMax-AI/MiniMax-MCP
neka-nat/freecad-mcp
mixelpixx/KiCAD-MCP-Server
samuelgursky/davinci-resolve-mcp
open-webui/mcpo
CodeGraphContext/CodeGraphContext
datagouv/datagouv-mcp
Mcp-Brasil/mcp-brasil
PrefectHQ/fastmcp
timescale/pg-aiguide
Vexa-ai/vexa
"
for r in $REPOS; do
  n=$(echo "$r" | tr '/' '_')
  [ -d "$DEST/$n" ] && continue
  timeout 180 git clone --depth 1 --quiet "https://github.com/$r" "$DEST/$n" 2>/dev/null \
    && echo "OK   $r" || { echo "FAIL $r"; rm -rf "$DEST/$n"; }
done
echo CLONE_DONE
