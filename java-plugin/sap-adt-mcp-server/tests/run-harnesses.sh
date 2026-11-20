#!/usr/bin/env bash
# Compiles and runs every standalone Java harness of the plugin (see docs/verification.md).
# Run from the repository root. Uses javac/java from JAVA_HOME (JDK 17 or newer) and the
# bundled gson jar; needs no Eclipse jars and no network. Exits non-zero on the first failure.
set -euo pipefail

project=java-plugin/sap-adt-mcp-server
plugin="$project/com.sap.adt.mcp.server.plugin"
gson="$plugin/gson-2.11.0.jar"
separator=':'
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) separator=';' ;; esac
javac="${JAVA_HOME:?JAVA_HOME must point at a JDK}/bin/javac"
java="$JAVA_HOME/bin/java"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# name, package, extra class path, arguments
run() {
    local name=$1 package=$2 extra_cp=$3
    shift 3
    local classes="$work/$name"
    mkdir "$classes"
    # Git Bash on Windows: the JDK needs a Windows path inside a ';'-separated class path.
    if command -v cygpath >/dev/null; then classes=$(cygpath -w "$classes"); fi
    "$javac" --release 17 -encoding UTF-8 -cp "$gson" -sourcepath "$plugin/src" \
        -d "$classes" "$project/tests/$name.java"
    "$java" -ea -cp "$classes$separator$gson$extra_cp" "$package.$name" "$@"
    echo "== $name passed"
}

run PackagePolicyRegression com.sap.adt.mcp.server ''
run LocalPolicyRegression com.sap.adt.mcp.server ''
run LegacySwitchRegression com.sap.adt.mcp.server ''
run RelayLinkRegression com.sap.adt.mcp.server '' "$project/tests/link-vectors.json"
run RelayEnrollmentRegression com.sap.adt.mcp.server ''
run PairingRegression com.sap.adt.mcp.server ''
run StreamRequestsRegression com.sap.adt.mcp.server ''
run ToolCatalogRegression com.sap.adt.mcp.tools "$separator$plugin" "$plugin/resources/tools.json"
run TunnelProtocolRegression com.sap.adt.mcp.server.e2e ''
run InnerKeysRegression com.sap.adt.mcp.server.e2e ''
run InnerChannelRegression com.sap.adt.mcp.server.e2e ''
echo "All Java harnesses passed."
