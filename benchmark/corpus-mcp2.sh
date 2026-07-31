#!/usr/bin/env bash
# Second MCP batch: SMALLER servers with real capability surface (network gear,
# Linux hosts, containers, trading, telephony, LMS). Chosen because mature
# projects gate centrally and are correctly suppressed -- see corpus-agents.md.
DEST="$1"; mkdir -p "$DEST"
REPOS="
jeff-nasseri/mikrotik-mcp
rhel-lightspeed/linux-mcp-server
portainer/portainer-mcp
dinglebear-ai/unraid
zb-ss/servonaut
cbcoutinho/nextcloud-mcp-server
codeofaxel/Kiln
psyb0t/mt5-httpapi
AgentLineHQ/AgentLine
vishalsachdev/canvas-mcp
apache/doris-mcp-server
arm/mcp
aplavin/julia-mcp
andrewbartels1/SolidworksMCP-python
oaslananka/kicad-mcp-pro
hhopke/intervals-icu-mcp
MarioDeFelipe/sap-datasphere-mcp
awslabs/threat-modeling-mcp-server
ReyemTech/mcp-canada
SharkyND/mcp-atlassian
Blazemeter/bzm-mcp
boettiger-lab/mcp-data-server
speedpy/speedpy
thomas-villani/all2md
MockLoop/mockloop-mcp
"
for r in $REPOS; do
  n=$(echo "$r" | tr '/' '_')
  [ -d "$DEST/$n" ] && continue
  timeout 180 git clone --depth 1 --quiet "https://github.com/$r" "$DEST/$n" 2>/dev/null \
    && echo "OK   $r" || { echo "FAIL $r"; rm -rf "$DEST/$n"; }
done
echo CLONE_DONE
