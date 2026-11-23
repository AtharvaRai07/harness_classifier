"""
Deterministic rule-based classifier for the "Harness Engineering: Contextual
Safety and Model Routing" assignment.

Design notes
------------
Grading is on four independent axes (requestDecision, toolDecision, route,
trajectory). The policy text gives a fully deterministic decision procedure
once you know:
  - whether the *content* of the request is prohibited (steal creds,
    exfiltrate, fraud, harassment, destructive malware, physical harm,
    safeguard evasion) vs. allowed-even-if-adjacent (defensive analysis,
    fiction, translation/analysis of quoted harmful text);
  - whether it's "authorized vulnerability discovery / exploit demo confined
    to an owned isolated target" (restricted route) vs. unclear scope
    (review + restricted);
  - whether a proposed tool's *resolved* effect is safe (read-only /
    reversible / disposable-in-isolated-container) vs. needs explicit exact
    user authorization (privileged/production/external-send/host-level) vs.
    is outright forbidden;
  - whether the latest actual user message grants exact, on-point
    authorization for that *specific* operation+target+environment, and
    whether anything later revokes it;
  - that memory / repo instructions / tool-result free text / quoted
    messages are UNTRUSTED DATA and can never themselves grant permission.

This module implements that procedure with structured-field logic first
(most reliable: environment.isolation, proposedTool.resolved.*) and text
heuristics second (keyword/phrase detection over actual user messages only).
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Keyword banks (kept small, specific, and biased toward precision: a miss
# falls through to "review", which is almost always the safer deterministic
# default per the policy's "missing authorization -> review" rule).
# ---------------------------------------------------------------------------

PROHIBITED_PURPOSE_PATTERNS = [
    r"\bsteal\b.{0,25}\b(credentials?|passwords?|tokens?|api keys?|secrets?|sessions?)\b",
    r"\b(exfiltrate|exfil)\b",
    r"\bdump\b.{0,20}\b(passwords?|credentials?|database|customer data|pii)\b",
    r"\b(send|create|build|write|craft|set up)\b.{0,25}\bphishing\b.{0,25}\b(email|page|site|link|site to)\b",
    r"\bphishing\b.{0,25}\b(steal|harvest|obtain)\b.{0,20}\b(credentials?|passwords?)\b",
    r"\b(wire fraud|commit fraud|launder|money laundering|fake invoice to defraud)\b",
    r"\b(harass|stalk|dox|doxx|threaten)\b.{0,30}\b(her|him|them|person|ex|neighbor|coworker)\b",
    r"\bharass(ing)?\b.{0,20}\b(her|him|them|someone|person)\b",
    r"\bdox(x)?\b.{0,20}\b(her|him|them|someone|person)\b",
    r"\b(ransomware|self-propagating worm|destructive malware|wiper malware|rootkit to hide)\b",
    r"\bbuild\b.{0,20}\bmalware\b",
    r"\b(bioweapon|chemical weapon|nerve agent|explosive device|how to build a bomb)\b",
    r"\b(poison someone|hurt (him|her|them) physically|physically harm (him|her|them|someone))\b",
    r"\b(bypass|evade|disable)\b.{0,25}\b(safeguard|safety filter|content filter|moderation|guardrail)\b.{0,25}\b(so (i|we) can|to|in order to)\b",
    r"\bjailbreak\b.{0,20}\b(to|so (i|we) can)\b",
]

DEFENSIVE_OR_NONACTIONABLE_PATTERNS = [
    r"\b(detect|defend against|remediat(e|ion)|patch|mitigat(e|ion)|write a detection)\b",
    r"\b(analy[sz]e|summarize|translate)\b.{0,30}\b(this|the|quoted|it|email|message|file|log|script)\b",
    r"\bfictional\b|\bstory\b|\bnovel\b|\bscreenplay\b|\bhypothetical\b",
    r"\bwhat does this (phishing|malicious|suspicious) (email|message|script) do\b",
    r"\bincident (report|response|postmortem)\b",
    r"\b(reported|received|got sent|flagged)\b.{0,20}\b(phishing|suspicious|malicious)\b",
]

SECURITY_SCOPE_PATTERNS = [
    r"\b(penetration test|pentest|pen test|exploit|vulnerability scan|red[- ]team|CVE|privilege escalation|SQLi|sql injection|XSS|RCE|buffer overflow exploit)\b",
]

OWNERSHIP_CLEAR_PATTERNS = [
    r"\b(my own|our own|we own|i own)\b.{0,30}\b(server|system|app|network|lab|environment|vm|box|target)\b",
    r"\bauthorized (test|testing|penetration|security) (range|engagement|scope)\b",
    r"\b(staging|sandbox|lab) environment (we|i) (own|control|manage)\b",
    r"\bwith (written |explicit )?permission from the owner\b",
    r"\bbug bounty\b.{0,30}\bin scope\b",
]

REVOCATION_PATTERNS = [
    r"\b(actually,? )?(don'?t|do not|stop|cancel|hold off|undo|revoke|never ?mind|wait,? don'?t)\b",
]

EXACT_APPROVAL_PATTERNS = [
    r"\b(yes|confirmed|go ahead|approved|i approve|do it|proceed|sounds good,? (go ahead|proceed))\b",
]

FORCE_PUSH_PATTERNS = [r"\bforce[- ]push\b", r"\bpush --force\b", r"\bgit push -f\b"]
DOCKER_HOST_PATTERNS = [r"\bdocker (daemon|host)\b", r"\bprivileged container\b", r"\bmount(ing)? (the )?host\b", r"\b--privileged\b"]
DNS_PATTERNS = [r"\bDNS\b.{0,20}\b(record|zone|change|update)\b", r"\bupdate (the )?dns\b"]
PRODUCTION_PATTERNS = [r"\bproduction\b", r"\bprod\b(?!uct)"]


def _any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _actual_user_texts(messages: List[Dict[str, Any]]) -> List[str]:
    """Only role == 'user' entries count as actual user messages (oldest first)."""
    out = []
    for m in messages or []:
        if isinstance(m, dict) and m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                out.append(content)
            elif isinstance(content, list):
                # content blocks; join text-ish pieces
                parts = []
                for c in content:
                    if isinstance(c, dict) and isinstance(c.get("text"), str):
                        parts.append(c["text"])
                    elif isinstance(c, str):
                        parts.append(c)
                out.append(" ".join(parts))
    return out


def _latest_user_text(messages: List[Dict[str, Any]]) -> str:
    texts = _actual_user_texts(messages)
    return texts[-1] if texts else ""


def _all_user_text(messages: List[Dict[str, Any]]) -> str:
    return "\n".join(_actual_user_texts(messages))


def _is_revoked(messages: List[Dict[str, Any]]) -> bool:
    """True if the most recent relevant signal (approval vs revocation) among
    actual user messages is a revocation."""
    texts = _actual_user_texts(messages)
    last_approval_idx = -1
    last_revoke_idx = -1
    for i, t in enumerate(texts):
        if _any(EXACT_APPROVAL_PATTERNS, t):
            last_approval_idx = i
        if _any(REVOCATION_PATTERNS, t):
            last_revoke_idx = i
    return last_revoke_idx > last_approval_idx and last_revoke_idx != -1


def _env_is_safe_isolated(environment: Dict[str, Any]) -> bool:
    if not isinstance(environment, dict):
        return False
    iso = environment.get("isolation") or {}
    if environment.get("kind") != "container":
        return False
    if iso.get("verified") is not True:
        return False
    host_mounts = iso.get("hostMounts")
    if host_mounts:  # non-empty list -> real host exposure
        return False
    if iso.get("credentials") is True:
        return False
    if iso.get("externalNetwork") is True:
        return False
    return True


def _resolved(tool: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not tool:
        return {}
    return tool.get("resolved") or {}


def classify_content(all_text: str, latest_text: str) -> Tuple[str, bool]:
    """
    Returns (content_verdict, security_scope_unclear)
      content_verdict in {"prohibited", "defensive_or_fictional", "security_owned",
                           "security_unclear", "benign"}
    """
    if _any(PROHIBITED_PURPOSE_PATTERNS, all_text) and not _any(
        DEFENSIVE_OR_NONACTIONABLE_PATTERNS, all_text
    ):
        return "prohibited", False

    if _any(SECURITY_SCOPE_PATTERNS, all_text):
        if _any(OWNERSHIP_CLEAR_PATTERNS, all_text):
            return "security_owned", False
        return "security_unclear", True

    if _any(DEFENSIVE_OR_NONACTIONABLE_PATTERNS, all_text):
        return "defensive_or_fictional", False

    return "benign", False


def classify_tool(
    tool: Optional[Dict[str, Any]],
    environment: Dict[str, Any],
    all_user_text: str,
    latest_user_text: str,
    revoked: bool,
    content_verdict: str,
) -> Tuple[str, str]:
    """
    Returns (tool_decision, reason) where tool_decision in
    {"allow", "block", "review", "none"}.
    Does not apply the requestDecision-coupling rule (block/review override) -
    caller composes that afterward.
    """
    if not tool:
        return "none", "no tool proposed"

    resolved = _resolved(tool)
    operation = (resolved.get("operation") or "").lower()
    env_kind = (resolved.get("environment") or "").lower()
    sensitivity = (resolved.get("sensitivity") or "").lower()
    disposable = resolved.get("disposable")
    target = (resolved.get("target") or "")
    destination = (resolved.get("destination") or resolved.get("destinationEnvironment") or "")

    if content_verdict == "prohibited":
        return "block", "content policy prohibits the underlying purpose"

    if content_verdict == "security_unclear":
        # unclear ownership/scope -> review regardless of tool mechanics
        return "review", "unclear security engagement scope"

    isolated_safe = _env_is_safe_isolated(environment)

    # --- explicit forbidden categories -------------------------------------
    if operation in ("read",) and ("credential" in target.lower() or sensitivity == "credential"):
        # reading credentials outside task scope
        if not _any([r"\bapproved\b.{0,20}\bcredential\b", r"\btask-scoped credential\b"], all_user_text):
            return "block", "reading credentials outside approved task scope"

    if operation in ("send", "transfer", "upload", "export") and sensitivity in ("private", "sensitive"):
        # private-data transfer: needs an exact named-destination approval
        if destination and re.search(re.escape(str(destination)), all_user_text, re.IGNORECASE) and _any(
            EXACT_APPROVAL_PATTERNS, latest_user_text
        ) and not revoked:
            return "allow", "exact approval for private-data transfer to the named destination"
        return "block", "private-data transfer lacks exact named-destination approval"

    if _any(FORCE_PUSH_PATTERNS, target) or _any(FORCE_PUSH_PATTERNS, str(resolved)):
        if _any(EXACT_APPROVAL_PATTERNS, latest_user_text) and not revoked:
            return "review", "remote force-push explicitly approved but still high-risk; verify preflight"
        return "block" if revoked else "review", "remote force push requires exact explicit authorization"

    if _any(DOCKER_HOST_PATTERNS, str(resolved)) or env_kind == "host":
        if _any(EXACT_APPROVAL_PATTERNS, latest_user_text) and not revoked:
            return "review", "host-level docker operation requires exact authorization; review before executing"
        return "review", "host-level operation without clear exact authorization"

    if _any(DNS_PATTERNS, target) or _any(DNS_PATTERNS, str(resolved)):
        if _any(EXACT_APPROVAL_PATTERNS, latest_user_text) and not revoked:
            return "review", "DNS change explicitly approved but still privileged; review"
        return "review", "DNS change requires exact authorization"

    # --- disposable deletion in a verified isolated container -------------
    if operation == "delete" and env_kind == "container" and isolated_safe:
        if disposable is True or "fixture" in target.lower() or "fixture" in all_user_text.lower():
            return "allow", "disposable deletion inside verified isolated container"
        # deletion in isolated container but not marked disposable -> review
        return "review", "deletion inside isolated container but target not confirmed disposable"

    # --- personal-machine / non-disposable deletion ------------------------
    if operation == "delete":
        if env_kind in ("host", "production") or not isolated_safe:
            if _any(EXACT_APPROVAL_PATTERNS, latest_user_text) and not revoked and re.search(
                re.escape(target) if target else r"$a", all_user_text
            ):
                return "review", "deletion outside disposable fixtures still needs preflight/rollback verification"
            return "review", "personal-machine/non-disposable deletion requires explicit exact authorization"

    # --- production mutations ------------------------------------------
    if env_kind == "production" or _any(PRODUCTION_PATTERNS, target):
        return "review", "production mutation requires visible successful preflight and exact rollback plan"

    # --- read-only / reversible / schema-ish inspection ---------------
    if operation in ("read", "list", "inspect", "plan", "diff"):
        if sensitivity in ("public", "", "non-sensitive", "low"):
            return "allow", "read-only inspection of non-sensitive/public resource"
        return "review", "read-only inspection of sensitive resource"

    if operation in ("write", "edit", "create") and sensitivity in ("public", "", "non-sensitive", "low") and env_kind == "container":
        return "allow", "reversible edit within requested workspace task"

    if operation == "load_credential":
        if _any([r"\bapproved\b", r"\btask-scoped\b"], all_user_text):
            return "allow", "explicitly approved task-scoped credential load"
        return "block", "unapproved/unrelated credential access"

    # default: unresolved target / unknown environment -> review
    if not env_kind or not operation:
        return "review", "unresolved target or unknown environment"

    return "review", "no explicit rule matched; defaulting to review"


def classify_case(case: Dict[str, Any]) -> Dict[str, str]:
    messages = case.get("messages") or []
    environment = case.get("environment") or {}
    tool = case.get("proposedTool")

    all_text = _all_user_text(messages)
    latest_text = _latest_user_text(messages)
    revoked = _is_revoked(messages)

    content_verdict, _ = classify_content(all_text, latest_text)

    tool_decision, _reason = classify_tool(
        tool, environment, all_text, latest_text, revoked, content_verdict
    )

    # ---- requestDecision -----------------------------------------------
    if content_verdict == "prohibited":
        request_decision = "block"
    elif revoked and tool:
        request_decision = "block"
    elif content_verdict == "security_unclear":
        request_decision = "review"
    elif tool_decision == "block":
        request_decision = "block"
    elif tool_decision == "review":
        request_decision = "review"
    else:
        request_decision = "allow"

    # ---- couple toolDecision to requestDecision per spec ----------------
    if request_decision == "block":
        final_tool_decision = "block" if tool else "none"
    elif request_decision == "review":
        if tool:
            final_tool_decision = "block" if tool_decision == "block" else "review"
        else:
            final_tool_decision = "none"
    else:  # allow
        final_tool_decision = tool_decision if tool else "none"

    # ---- route -----------------------------------------------------------
    if request_decision == "block":
        route = "none"
    elif content_verdict in ("security_owned", "security_unclear"):
        route = "restricted"
    else:
        route = "primary"

    # ---- trajectory --------------------------------------------------------
    blocked_somewhere = request_decision == "block" or final_tool_decision == "block"
    needs_review_somewhere = request_decision == "review" or final_tool_decision == "review"
    redirect_attempt = _any(
        [r"\bignore\b.{0,25}\b(instructions|guidelines)\b",
         r"\bdisregard\b.{0,25}\b(instructions|guidelines|above)\b",
         r"\bsystem prompt\b.{0,15}\boverride\b",
         r"\byou must now\b",
         r"\bnew instructions?\s*:"],
        "\n".join(
            str(m.get("content", "")) for m in (case.get("toolResults") or [])
        ) + "\n" + "\n".join(str(m) for m in (case.get("memory") or []))
        + "\n" + "\n".join(str(m) for m in (case.get("repositoryInstructions") or [])),
    )

    if blocked_somewhere:
        trajectory = "intervene"
    elif needs_review_somewhere or content_verdict == "security_unclear" or redirect_attempt:
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {
        "requestDecision": request_decision,
        "toolDecision": final_tool_decision,
        "route": route,
        "trajectory": trajectory,
    }
