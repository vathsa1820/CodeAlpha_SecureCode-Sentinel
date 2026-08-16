import hashlib
from typing import List, Dict, Tuple, Any
from app.models.findings import Finding
from app.analyzers.categories import map_finding_category, map_category_to_owasp, generate_fingerprint

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

CONFIDENCE_RANK = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

def generate_group_id(source_file: str, category: str, line: int) -> str:
    """
    Generate a stable, deterministic group identifier for correlated findings.
    """
    raw_str = f"{source_file}:{category}:{line}"
    digest = hashlib.md5(raw_str.encode("utf-8")).hexdigest()[:8]
    return f"group-{category.lower()}-L{line}-{digest}"

def correlate_findings(raw_findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """
    Correlate raw findings into logical findings preserving analyzer evidence, OWASP, fingerprints, and context.
    """
    if not raw_findings:
        return [], []

    # 1. Update finding categories using centralized category mapping
    for f in raw_findings:
        f.category = map_finding_category(f.rule_id, f.cwe, f.title)
        if not f.owasp:
            f.owasp = map_category_to_owasp(f.category)
        if not f.fingerprint:
            f.fingerprint = generate_fingerprint(
                f.category, f.cwe, f.source_file, f.line_start, f.line_end, f.rule_id
            )

    # 2. Group findings by (source_file, category, line_start)
    groups: Dict[Tuple[str, str, int], List[Finding]] = {}

    for f in raw_findings:
        matched_key = None
        for key in groups.keys():
            file_k, cat_k, line_k = key
            if (f.source_file or "input.py") == file_k and f.category == cat_k:
                if abs(f.line_start - line_k) <= 1:
                    matched_key = key
                    break

        if matched_key:
            groups[matched_key].append(f)
        else:
            key = (f.source_file or "input.py", f.category, f.line_start)
            groups[key] = [f]

    correlated_logical_findings: List[Finding] = []

    # 3. Build logical finding representations for each group
    for (src_file, category, start_line), group_items in groups.items():
        group_id = generate_group_id(src_file, category, start_line)

        # Collect unique detected_by analyzers list
        analyzers_list: List[str] = []
        for item in group_items:
            for tool in (item.detected_by or [item.analyzer]):
                if tool not in analyzers_list:
                    analyzers_list.append(tool)

        # Collect preserved analyzer-specific evidence
        analyzer_evidence_list: List[Dict[str, Any]] = []
        seen_tool_rules = set()
        for item in group_items:
            for ev in (item.analyzer_evidence or []):
                key = (ev.get("analyzer"), ev.get("rule_id"))
                if key not in seen_tool_rules:
                    seen_tool_rules.add(key)
                    analyzer_evidence_list.append(ev)

            if not item.analyzer_evidence:
                key = (item.analyzer, item.rule_id)
                if key not in seen_tool_rules:
                    seen_tool_rules.add(key)
                    analyzer_evidence_list.append({
                        "analyzer": item.analyzer,
                        "rule_id": item.rule_id,
                        "confidence": item.confidence,
                        "severity": item.severity,
                    })

        # Determine highest severity and confidence in group
        highest_sev = max(group_items, key=lambda x: SEVERITY_RANK.get(x.severity.upper(), 1)).severity
        highest_conf = max(group_items, key=lambda x: CONFIDENCE_RANK.get(x.confidence.upper(), 0)).confidence

        # Select primary item for descriptive fields
        primary = group_items[0]
        cwe_val = next((item.cwe for item in group_items if item.cwe), primary.cwe)
        owasp_val = next((item.owasp for item in group_items if item.owasp), map_category_to_owasp(category))

        min_line = min(item.line_start for item in group_items)
        max_line = max(item.line_end for item in group_items)

        code_snippet = next((item.code for item in group_items if item.code), None)
        source_ctx = next((item.source_context for item in group_items if item.source_context), None)

        fingerprint = generate_fingerprint(category, cwe_val, src_file, min_line, max_line, primary.rule_id)

        evidence = {
            "source": code_snippet or f"Line {min_line}",
            "line_start": min_line,
            "line_end": max_line,
            "matched_rule": primary.rule_id,
            "analyzers": analyzers_list,
        }

        logical_finding = Finding(
            id=f"logical-{group_id}",
            finding_group_id=group_id,
            fingerprint=fingerprint,
            analyzer=primary.analyzer,
            detected_by=analyzers_list,
            rule_id=primary.rule_id,
            title=primary.title,
            description=primary.description,
            severity=highest_sev,
            confidence=highest_conf,
            category=category,
            cwe=cwe_val,
            owasp=owasp_val,
            line_start=min_line,
            line_end=max_line,
            code=code_snippet,
            source_file=src_file,
            evidence=evidence,
            analyzer_evidence=analyzer_evidence_list,
            source_context=source_ctx,
        )

        # Annotate raw findings with group_id and detected_by
        for item in group_items:
            item.finding_group_id = group_id
            item.detected_by = analyzers_list

        correlated_logical_findings.append(logical_finding)

    return correlated_logical_findings, raw_findings
