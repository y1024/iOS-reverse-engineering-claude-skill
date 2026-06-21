#!/usr/bin/env bash
# audit-vulnerabilities.sh — Audit an extracted iOS app for static security vulnerabilities
#
# Complements find-api-calls.sh (API extraction) and deep-secret-scan.sh (secrets) by
# hunting iOS-specific vulnerability CLASSES: insecure local storage, WebView/JS-bridge
# abuse, deeplink/URL-scheme hijack, weak crypto/RNG, biometric-bypass patterns, sensitive
# logging, ATS detail, privacy/tracking, entitlements risk, and debug artifacts.
#
# Each finding carries: Category, Severity, Confidence, FP-likelihood, Evidence (file:line).
# Proximity-based findings (logging-of-secrets, token-in-UserDefaults, RNG-for-tokens) use a
# one-line co-occurrence match: lines containing BOTH a trigger and a secret keyword. This is a
# pragmatic signal — mark them CONFIDENCE=MEDIUM and review multi-line cases manually.
set -euo pipefail

usage() {
  cat <<EOF
Usage: audit-vulnerabilities.sh <analysis-dir> [OPTIONS]

Audit an extracted iOS app for static security vulnerabilities (insecure storage,
WebView/JS-bridge, deeplink hijack, weak crypto, biometric bypass, sensitive logging,
ATS detail, privacy/tracking, entitlements risk, debug artifacts).

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --storage         Insecure local storage only
  --webview         WebView / JS-bridge only
  --deeplink        Deeplink / URL-scheme only
  --crypto          Weak crypto / RNG only
  --auth             Biometric / local-auth only
  --logging         Sensitive-data logging only
  --network         ATS / cleartext / insecure WS only
  --privacy         Tracking / clipboard / screen-capture only
  --entitlements    Entitlements risk only
  --debug           Debug / staging artifacts only
  --all             Audit all categories (default)
  --severity LEVEL  Minimum severity: critical, high, medium, low, info (default: low)
  --report FILE     Export results as structured Markdown report
  -h, --help        Show this help message

Output:
  Findings table: ID | Category | Severity | Confidence | FP-likelihood | Description | Evidence
  Designed for LLM triage using the FP-likelihood field to deprioritize likely false positives.
EOF
  exit 0
}

export LC_ALL=C

ANALYSIS_DIR=""
DO_STORAGE=false
DO_WEBVIEW=false
DO_DEEPLINK=false
DO_CRYPTO=false
DO_AUTH=false
DO_LOGGING=false
DO_NETWORK=false
DO_PRIVACY=false
DO_ENTITLEMENTS=false
DO_DEBUG=false
DO_ALL=true
MIN_SEVERITY="low"
REPORT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage)      DO_STORAGE=true;      DO_ALL=false; shift ;;
    --webview)      DO_WEBVIEW=true;      DO_ALL=false; shift ;;
    --deeplink)     DO_DEEPLINK=true;     DO_ALL=false; shift ;;
    --crypto)       DO_CRYPTO=true;       DO_ALL=false; shift ;;
    --auth)          DO_AUTH=true;         DO_ALL=false; shift ;;
    --logging)      DO_LOGGING=true;      DO_ALL=false; shift ;;
    --network)      DO_NETWORK=true;      DO_ALL=false; shift ;;
    --privacy)      DO_PRIVACY=true;     DO_ALL=false; shift ;;
    --entitlements) DO_ENTITLEMENTS=true; DO_ALL=false; shift ;;
    --debug)        DO_DEBUG=true;        DO_ALL=false; shift ;;
    --all)          DO_ALL=true; shift ;;
    --severity)     MIN_SEVERITY="$2"; shift 2 ;;
    --report)       REPORT_FILE="$2"; shift 2 ;;
    -h|--help)      usage ;;
    -*)             echo "Error: Unknown option $1" >&2; usage ;;
    *)              ANALYSIS_DIR="$1"; shift ;;
  esac
done

if [[ -z "$ANALYSIS_DIR" ]]; then
  echo "Error: No analysis directory specified." >&2
  usage
fi
if [[ ! -d "$ANALYSIS_DIR" ]]; then
  echo "Error: Directory not found: $ANALYSIS_DIR" >&2
  exit 1
fi

GREP_OPTS="-rnE --include=*.h --include=*.m --include=*.swift --include=*.txt --include=*.plist --include=*.json --include=*.c"

severity_rank() {
  case "$1" in
    critical) echo 5 ;; high) echo 4 ;; medium) echo 3 ;; low) echo 2 ;; info) echo 1 ;; *) echo 0 ;;
  esac
}
MIN_RANK=$(severity_rank "$MIN_SEVERITY")
severity_passes() { [[ $(severity_rank "$1") -ge "$MIN_RANK" ]]; }

# Indexed arrays (bash 3.2 compatible)
F_ID=()
F_CAT=()
F_SEV=()
F_CONF=()
F_FP=()
F_DESC=()
F_EVID=()
NEXT_ID=1

add_finding() {
  # $1 category $2 severity $3 confidence $4 fp_likelihood $5 description $6 evidence
  local cat="$1" sev="$2" conf="$3" fp="$4" desc="$5" evidence="${6:-(no evidence)}"
  if ! severity_passes "$sev"; then
    return
  fi
  F_ID+=("$NEXT_ID")
  F_CAT+=("$cat")
  F_SEV+=("$sev")
  F_CONF+=("$conf")
  F_FP+=("$fp")
  F_DESC+=("$desc")
  F_EVID+=("$evidence")
  NEXT_ID=$((NEXT_ID + 1))
}

# match: grep a single regex, dedup by matched line, return evidence lines (file:line:match).
match() {
  local case_flag=""
  [[ "$1" == "-i" ]] && { case_flag="-i"; shift; }
  local pattern="$1"
  # shellcheck disable=SC2086
  grep $GREP_OPTS $case_flag "$pattern" "$ANALYSIS_DIR" 2>/dev/null | sort -u | head -25 || true
}

# proximity: keep lines matching BOTH a trigger and a keyword (one-line co-occurrence).
proximity() {
  local case_flag=""
  [[ "$1" == "-i" ]] && { case_flag="-i"; shift; }
  local trigger="$1" keyword="$2"
  # shellcheck disable=SC2086
  grep $GREP_OPTS $case_flag "$trigger" "$ANALYSIS_DIR" 2>/dev/null \
    | grep -iE "$keyword" 2>/dev/null | sort -u | head -25 || true
}

# plist_bool: read a boolean-ish key from Info.plist. Echoes "true"/"false"/"" (empty=absent).
plist_val() {
  local key="$1" plist="${2:-$ANALYSIS_DIR/Info.plist}"
  [[ -f "$plist" ]] || { echo ""; return; }
  if command -v plutil >/dev/null 2>&1; then
    plutil -extract "$key" raw "$plist" 2>/dev/null || true
  elif command -v /usr/libexec/PlistBuddy >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null || true
  fi
}

echo "=== iOS Vulnerability Audit: $ANALYSIS_DIR ==="
echo "Minimum severity: $MIN_SEVERITY (rank $MIN_RANK)"
echo

# =====================================================================
# 1. Insecure local storage
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_STORAGE" == true ]]; then
  echo "--- Insecure Local Storage ---"

  res=$(proximity -i 'UserDefaults|standardUserDefaults' 'token|password|secret|credential|jwt|bearer|auth_token|apikey|api_key')
  [[ -n "$res" ]] && add_finding "Storage" "medium" "medium" "medium" \
    "Sensitive value written to UserDefaults (not Keychain)" "$res"

  res=$(match -i 'kSecAttrAccessibleAlwaysThisDeviceOnly|kSecAttrAccessibleAlways')
  [[ -n "$res" ]] && add_finding "Storage" "high" "high" "low" \
    "Keychain item accessible when device unlocked / always (weak accessibility class)" "$res"

  res=$(match 'NSPersistentContainer|NSManagedObject|RLMRealm|Realm\.configuration')
  [[ -n "$res" ]] && add_finding "Storage" "low" "medium" "medium" \
    "Local database (CoreData/Realm/SQLite) — verify at-rest encryption" "$res"

  res=$(match -i '\.sqlite|\.realm|\.db["[:space:]]')
  [[ -n "$res" ]] && add_finding "Storage" "low" "low" "medium" \
    "Local database file reference — check if encrypted" "$res"

  # Info.plist: file sharing exposes Documents via iTunes/Finder
  fshare=$(plist_val "UIFileSharingEnabled")
  if [[ "$fshare" == "true" || "$fshare" == "YES" ]]; then
    add_finding "Storage" "high" "high" "low" \
      "UIFileSharingEnabled=true exposes Documents/ via iTunes/Finder file sharing" \
      "Info.plist: UIFileSharingEnabled=$fshare"
  fi

  openinplace=$(plist_val "LSSupportsOpeningDocumentsInPlace")
  if [[ "$openinplace" == "true" || "$openinplace" == "YES" ]]; then
    add_finding "Storage" "medium" "medium" "low" \
      "LSSupportsOpeningDocumentsInPlace=true exposes app Documents to other apps" \
      "Info.plist: LSSupportsOpeningDocumentsInPlace=$openinplace"
  fi

  res=$(match -i 'FileProtectionType\.none|NSURLFileProtectionNone|\.completeFileProtection|protectionType.*none')
  if [[ -n "$(match -i 'FileProtectionType|NSURLFileProtectionKey')" ]]; then
    if [[ -n "$res" ]]; then
      add_finding "Storage" "medium" "medium" "medium" \
        "Data protection explicitly set to None (no at-rest encryption for that file)" "$res"
    fi
  else
    add_finding "Storage" "low" "low" "high" \
      "No NSURLFileProtectionKey/FileProtectionType usage found — sensitive files may default to incomplete protection" \
      "(absence-based — confirm app stores sensitive data)"
  fi

  echo
fi

# =====================================================================
# 2. WebView / JS-bridge
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_WEBVIEW" == true ]]; then
  echo "--- WebView / JS-bridge ---"

  res=$(match 'UIWebView')
  [[ -n "$res" ]] && add_finding "WebView" "medium" "high" "low" \
    "Deprecated UIWebView (security unsupported, App Store rejects)" "$res"

  res=$(match 'allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs')
  [[ -n "$res" ]] && add_finding "WebView" "high" "medium" "medium" \
    "WKWebView allows file:// / universal access from file URLs (local file XSS → native bridge)" "$res"

  res=$(match 'addScriptMessageHandler|scriptMessageHandler|WKUserContentController.*add')
  [[ -n "$res" ]] && add_finding "WebView" "medium" "medium" "medium" \
    "WKWebView native bridge (addScriptMessageHandler) — review exposed handler names" "$res"

  res=$(match 'evaluateJavaScript')
  [[ -n "$res" ]] && add_finding "WebView" "low" "medium" "medium" \
    "evaluateJavaScript usage — review if dynamic/untrusted strings are injected" "$res"

  res=$(proximity -i 'loadHTMLString|loadFileURL|loadData\(' 'http|url|request|response|html')
  [[ -n "$res" ]] && add_finding "WebView" "medium" "medium" "high" \
    "WKWebView loads local/inline content with URL-like data — review for injection" "$res"

  res=$(proximity -i 'WKNavigationDelegate|didReceiveAuthenticationChallenge|URLAuthenticationChallenge' 'webView|wkwebview|trust|credential')
  [[ -n "$res" ]] && add_finding "WebView" "medium" "medium" "medium" \
    "WebView authentication challenge handler — check it isn't bypassing TLS validation" "$res"

  echo
fi

# =====================================================================
# 3. Deeplink / URL-scheme
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_DEEPLINK" == true ]]; then
  echo "--- Deeplink / URL-scheme ---"

  # List custom URL schemes from Info.plist (robust: convert whole plist to JSON, grep schemes)
  if [[ -f "$ANALYSIS_DIR/Info.plist" ]] && command -v plutil >/dev/null 2>&1; then
    schemes=$(plutil -convert json -o - "$ANALYSIS_DIR/Info.plist" 2>/dev/null \
              | grep -oE '"CFBundleURLSchemes"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
              | grep -oE '"[^"]+"' | grep -vE 'CFBundleURLSchemes' | sort -u || true)
  fi
  if [[ -n "$schemes" ]]; then
    add_finding "Deeplink" "low" "high" "low" \
      "Custom URL scheme(s) declared — review for scheme-hijack risk" \
      "$schemes"
  fi

  res=$(match 'application:openURL:|openURLContexts|scene.*openURLContexts|application:continueUserActivity:|getContinuationURL')
  [[ -n "$res" ]] && add_finding "Deeplink" "low" "medium" "low" \
    "Deeplink / universal-link entry point — review input validation" "$res"

  # Token/code received via scheme → high risk of token theft via scheme hijack
  res=$(proximity -i 'openURL|openURLContexts|continueUserActivity|getContinuationURL' 'token|code|access_token|oauth|auth_code|state')
  [[ -n "$res" ]] && add_finding "Deeplink" "high" "medium" "medium" \
    "Auth token/code handled in deeplink callback — vulnerable to scheme-hijack interception" "$res"

  res=$(match 'associated-domains|applinks:|activitycontinuation')
  [[ -n "$res" ]] && add_finding "Deeplink" "info" "medium" "low" \
    "Universal links / Handoff configured — review server-side apple-app-site-association + input validation" "$res"

  echo
fi

# =====================================================================
# 4. Weak crypto / RNG
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_CRYPTO" == true ]]; then
  echo "--- Weak Crypto / RNG ---"

  res=$(match 'kCCOptionECBMode|kCCAlgorithmECB|\.ecb|CipherMode\.ecb')
  [[ -n "$res" ]] && add_finding "Crypto" "high" "high" "low" \
    "ECB cipher mode used (deterministic, leaks patterns)" "$res"

  res=$(proximity -i 'arc4random|arc4random_uniform|rand\(\)|random\(\)' 'token|secret|key|password|nonce|otp|session|csrf')
  [[ -n "$res" ]] && add_finding "Crypto" "medium" "medium" "medium" \
    "Non-CSPRNG (arc4random/rand) used near a secret/token — use SecRandomCopyBytes" "$res"

  res=$(match 'CC_MD5|CC_SHA1|SHA1|MD5')
  [[ -n "$res" ]] && add_finding "Crypto" "medium" "medium" "medium" \
    "MD5/SHA1 used — weak for integrity/auth, avoid" "$res"

  res=$(match -i 'iv\s*=\s*"|initialization[_-]?vector\s*=\s*"|salt\s*=\s*@"|kCC.*IV.*"')
  [[ -n "$res" ]] && add_finding "Crypto" "high" "medium" "medium" \
    "Hardcoded IV/salt — destroys cryptographic soundness" "$res"

  res=$(proximity -i 'kCCAlgorithmAES|AES\.' 'key.*"|" *[A-Za-z0-9+/]{16,} *= *key|setKey')
  [[ -n "$res" ]] && add_finding "Crypto" "medium" "medium" "high" \
    "AES usage with possibly hardcoded key — confirm key source" "$res"

  res=$(match 'SecRandomCopyBytes')
  # If RNG-for-token found above but no SecRandomCopyBytes, note absence (handled by proximity finding).

  echo
fi

# =====================================================================
# 5. Biometric / local auth
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_AUTH" == true ]]; then
  echo "--- Biometric / Local Auth ---"

  res=$(match 'LAContext|evaluatePolicy|LAPolicyDeviceOwnerAuthenticationWithBiometrics|LAPolicyDeviceOwnerAuthentication')
  [[ -n "$res" ]] && add_finding "Auth" "info" "medium" "medium" \
    "LocalAuthentication used — review fallback handling (cancel/error paths) and server-side binding" "$res"

  res=$(proximity -i 'evaluatePolicy' 'success.*true|true.*success|allow|bypass|continue')
  [[ -n "$res" ]] && add_finding "Auth" "medium" "low" "high" \
    "evaluatePolicy result handling looks permissive — review biometric bypass potential" "$res"

  echo
fi

# =====================================================================
# 6. Sensitive-data logging
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_LOGGING" == true ]]; then
  echo "--- Sensitive-data Logging ---"

  res=$(proximity -i 'print\(|NSLog\(|os_log\(|Logger\.|\.debug\(' 'token|password|secret|credential|jwt|bearer|auth_token|apikey|api_key|private[_-]?key')
  [[ -n "$res" ]] && add_finding "Logging" "high" "medium" "medium" \
    "Logging call on same line as a secret keyword — likely logs sensitive data" "$res"

  res=$(proximity -i 'os_log\(' 'token|password|secret|credential|jwt|bearer|auth_token')
  # If os_log used with secrets and no %{private} redaction:
  if [[ -n "$res" ]] && [[ -z "$(match '\%\{private\}') " ]]; then
    add_finding "Logging" "medium" "low" "medium" \
      "os_log used near secrets without %{private} redaction" "$res"
  fi

  echo
fi

# =====================================================================
# 7. Network / ATS
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_NETWORK" == true ]]; then
  echo "--- Network / ATS ---"

  allows=$(plist_val "NSAppTransportSecurity.NSAllowsArbitraryLoads" "$ANALYSIS_DIR/Info.plist")
  if [[ "$allows" == "true" || "$allows" == "YES" ]]; then
    add_finding "Network" "high" "high" "low" \
      "ATS disabled globally (NSAllowsArbitraryLoads) — allows cleartext to any host" \
      "Info.plist: NSAllowsArbitraryLoads=$allows"
  fi

  allowsmedia=$(plist_val "NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia" "$ANALYSIS_DIR/Info.plist")
  if [[ "$allowsmedia" == "true" || "$allowsmedia" == "YES" ]]; then
    add_finding "Network" "medium" "high" "low" \
      "ATS allows arbitrary loads for media (cleartext media streams)" \
      "Info.plist: NSAllowsArbitraryLoadsForMedia=$allowsmedia"
  fi

  mintls=$(plist_val "NSAppTransportSecurity.NSMinimumTLSVersion" "$ANALYSIS_DIR/Info.plist")
  if [[ "$mintls" == "TLSv1.0" || "$mintls" == "TLSv1.1" ]]; then
    add_finding "Network" "high" "high" "low" \
      "ATS allows weak TLS ($mintls) — downgrade to TLSv1.2+" \
      "Info.plist: NSMinimumTLSVersion=$mintls"
  fi

  res=$(match -i 'NSExceptionAllowsInsecureHTTPLoads|NSRequiresForwardSecrecy.*false')
  [[ -n "$res" ]] && add_finding "Network" "medium" "medium" "low" \
    "ATS exception allows insecure HTTP / disables forward secrecy for a domain" "$res"

  res=$(match '"http://[^"]+"')
  [[ -n "$res" ]] && add_finding "Network" "medium" "medium" "medium" \
    "Hardcoded cleartext http:// URL — verify not used for sensitive traffic" "$res"

  res=$(match 'ws://[^"]')
  [[ -n "$res" ]] && add_finding "Network" "medium" "medium" "low" \
    "Insecure WebSocket (ws://) — unencrypted realtime channel" "$res"

  res=$(match -i 'disableEvaluation|AllowAll|trustAll|continueWithoutCredential|performDefaultHandling.*ServerTrust')
  [[ -n "$res" ]] && add_finding "Network" "high" "medium" "medium" \
    "Custom trust manager may bypass TLS validation" "$res"

  echo
fi

# =====================================================================
# 8. Privacy / tracking / screen-capture
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_PRIVACY" == true ]]; then
  echo "--- Privacy / Tracking ---"

  has_idfa=$(match 'advertisingIdentifier|ASIdentifierManager')
  has_att=$(match 'ATTrackingManager|requestTrackingAuthorization|AppTrackingTransparency')
  if [[ -n "$has_idfa" && -z "$has_att" ]]; then
    add_finding "Privacy" "medium" "medium" "low" \
      "IDFA access without App Tracking Transparency request prompt" "$has_idfa"
  fi

  res=$(proximity -i 'UIPasteboard|generalPasteboard|pasteboard' 'token|password|secret|credential|jwt|bearer|card|otp')
  [[ -n "$res" ]] && add_finding "Privacy" "medium" "medium" "medium" \
    "Pasteboard used with sensitive data — accessible by any app" "$res"

  # Screen-capture guard absence for sensitive apps (signal only)
  has_capture=$(match 'isCaptured|capturedDidChange|UIScreen.*isCaptured')
  if [[ -z "$has_capture" && -n "$(match -i 'bank|wallet|payment|card|otp|pin')" ]]; then
    add_finding "Privacy" "low" "low" "high" \
      "Sensitive-app keywords present but no screen-capture detection — screen recording could leak UI" \
      "(absence-based, low confidence)"
  fi

  echo
fi

# =====================================================================
# 9. Entitlements risk
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_ENTITLEMENTS" == true ]]; then
  echo "--- Entitlements Risk ---"

  ENT="$ANALYSIS_DIR/entitlements.plist"
  if [[ -f "$ENT" ]]; then
    if grep -q "com.apple.security.cs.disable-library-validation" "$ENT" 2>/dev/null; then
      add_finding "Entitlements" "medium" "high" "low" \
        "Library validation disabled (com.apple.security.cs.disable-library-validation) — widens dylib injection surface" \
        "entitlements.plist"
    fi
    if grep -q "application-groups" "$ENT" 2>/dev/null; then
      add_finding "Entitlements" "low" "medium" "low" \
        "App group(s) configured — shared container may leak data between apps" \
        "entitlements.plist"
    fi
    if grep -q "keychain-access-groups" "$ENT" 2>/dev/null; then
      add_finding "Entitlements" "low" "medium" "low" \
        "Shared keychain access group(s) — review cross-app credential sharing" \
        "entitlements.plist"
    fi
    if grep -qE "healthkit|contacts|homekit|location|microphone|camera" "$ENT" 2>/dev/null; then
      add_finding "Entitlements" "info" "medium" "low" \
        "Sensitive capability entitlement(s) present (health/contacts/homekit/location/av)" \
        "entitlements.plist"
    fi
  else
    echo "  (no entitlements.plist — skipping entitlement checks)"
  fi

  echo
fi

# =====================================================================
# 10. Debug / staging artifacts
# =====================================================================
if [[ "$DO_ALL" == true || "$DO_DEBUG" == true ]]; then
  echo "--- Debug / Staging Artifacts ---"

  res=$(proximity -i '#if\s*DEBUG|isDebug|debugMode' 'staging|http://|\.test|\.internal|localhost|admin|backdoor|skipVerification')
  [[ -n "$res" ]] && add_finding "Debug" "low" "medium" "medium" \
    "Debug-gated code references insecure endpoints/flags — risk of shipping debug behavior" "$res"

  res=$(match -i '"https?://[a-z0-9.-]*(staging|\.test|\.internal|localhost|10\.[0-9]+\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[a-z0-9.-]*"')
  [[ -n "$res" ]] && add_finding "Debug" "low" "medium" "low" \
    "Staging/internal/localhost URL — may be a leftover dev endpoint" "$res"

  res=$(match -i 'isTestflight|isBeta|isDebugMode')
  [[ -n "$res" ]] && add_finding "Debug" "info" "low" "low" \
    "Beta/testflight flag — review if it gates security controls" "$res"

  echo
fi

# =====================================================================
# Summary + report
# =====================================================================
echo "=== Vulnerability Audit Summary ==="
echo "Total findings: ${#F_ID[@]}"
echo

# Print findings table
if [[ ${#F_ID[@]} -gt 0 ]]; then
  printf "%-4s %-13s %-9s %-11s %-13s %s\n" "ID" "Category" "Severity" "Confidence" "FP-likelihood" "Description"
  printf "%-4s %-13s %-9s %-11s %-13s %s\n" "--" "--------" "--------" "----------" "-------------" "-----------"
  for i in "${!F_ID[@]}"; do
    printf "%-4s %-13s %-9s %-11s %-13s %s\n" "${F_ID[$i]}" "${F_CAT[$i]}" "${F_SEV[$i]}" "${F_CONF[$i]}" "${F_FP[$i]}" "${F_DESC[$i]}"
  done
fi
echo

echo "LLM_AUDIT_SUMMARY:TOTAL=${#F_ID[@]}"

# Markdown report
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# iOS Vulnerability Audit Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Minimum severity**: $MIN_SEVERITY"
    echo "**Total findings**: ${#F_ID[@]}"
    echo
    echo "## Findings Summary"
    echo
    echo "| ID | Category | Severity | Confidence | FP-likelihood | Description |"
    echo "|----|----------|----------|------------|---------------|-------------|"
    for i in "${!F_ID[@]}"; do
      echo "| ${F_ID[$i]} | ${F_CAT[$i]} | ${F_SEV[$i]} | ${F_CONF[$i]} | ${F_FP[$i]} | ${F_DESC[$i]} |"
    done
    echo
    echo "## Detailed Findings"
    echo
    for i in "${!F_ID[@]}"; do
      echo "### [${F_SEV[$i]}] #${F_ID[$i]} — ${F_CAT[$i]}: ${F_DESC[$i]}"
      echo
      echo "- **Severity**: ${F_SEV[$i]}"
      echo "- **Confidence**: ${F_CONF[$i]}"
      echo "- **FP-likelihood**: ${F_FP[$i]}"
      echo "- **Evidence**:"
      echo '```'
      echo "${F_EVID[$i]}"
      echo '```'
      echo
    done
    echo "---"
    echo
    echo "## LLM Triage Instructions"
    echo
    echo "Order of operations:"
    echo "1. Triage by **FP-likelihood** first — High-FP findings (absence-based, permissive-pattern, multi-line proximity) need manual confirmation before action."
    echo "2. Then by **Severity × Confidence**: critical/high + high-confidence = act now; medium = investigate."
    echo "3. For each finding, map the evidence (`file:line:match`) back to the decompiled/class-dumped code (Phase 8) to confirm exploitability."
    echo "4. **Proximity findings** (logging-of-secrets, token-in-UserDefaults, RNG-for-token) are one-line co-occurrence matches — review the surrounding function for multi-line cases the pattern missed."
    echo "5. Cross-reference with `deep-secret-scan.sh` (Phase 7) for the actual credential values, and `detect-protections.sh` (Phase 10) for whether anti-tampering would block dynamic confirmation."
    echo
    echo "### FP-likelihood legend"
    echo "- **Low**: direct API/flag match, high signal (e.g. `UIFileSharingEnabled=true`, ECB mode)."
    echo "- **Medium**: requires contextual confirmation (e.g. `evaluateJavaScript` present, JS-bridge intent unclear)."
    echo "- **High**: absence-based or permissive proximity; likely real but needs human review."
    echo
    echo "---"
    echo "_Report generated by ios-reverse-engineering-skill audit-vulnerabilities_"
  } > "$REPORT_FILE"
  echo "Report saved to: $REPORT_FILE"
fi

if [[ ${#F_ID[@]} -gt 0 ]]; then
  # Exit non-zero if any high/critical present (for scripting)
  has_high=0
  for i in "${!F_ID[@]}"; do
    case "${F_SEV[$i]}" in critical|high) has_high=1 ;; esac
  done
  [[ "$has_high" == 1 ]] && exit 1
fi
exit 0