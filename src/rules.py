from collections import Counter, defaultdict

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe",
    "procdump.exe",
    "psexec.exe",
    "rundll32.exe",
    "powershell.exe",
    "wmic.exe",
}

def _get_first(row, keys, default=None):
    for key in keys:
        if key in row:
            return row.get(key)
    return default

def rule_bruteforce(auth_rows, min_failures=5):
    findings = []
    counts = Counter()
    for row in auth_rows or []:
        success = _get_first(row, ["success", "ok", "authenticated"], default=True)
        if success:
            continue
        user = _get_first(row, ["user", "username", "account"], default="unknown")
        src_ip = _get_first(row, ["src_ip", "source_ip", "ip"], default="unknown")
        counts[(user, src_ip)] += 1
    for (user, src_ip), count in counts.items():
        if count >= min_failures:
            findings.append({
                "rule": "bruteforce",
                "etype": "user",
                "entity": user,
                "score": 3.0,
                "event": {
                    "src_ip": src_ip,
                    "failures": count,
                },
            })
    return findings

def rule_ip_churn(auth_rows, min_distinct_ips=3):
    findings = []
    ips_by_user = defaultdict(set)
    for row in auth_rows or []:
        user = _get_first(row, ["user", "username", "account"], default=None)
        src_ip = _get_first(row, ["src_ip", "source_ip", "ip"], default=None)
        if not user or not src_ip:
            continue
        ips_by_user[user].add(src_ip)
    for user, ips in ips_by_user.items():
        if len(ips) >= min_distinct_ips:
            findings.append({
                "rule": "ip_churn",
                "etype": "user",
                "entity": user,
                "score": 2.0,
                "event": {
                    "distinct_ips": sorted(ips),
                    "count": len(ips),
                },
            })
    return findings

def rule_suspicious_process(proc_rows):
    findings = []
    for row in proc_rows or []:
        proc = _get_first(row, ["process", "name", "image"], default="").lower()
        if not proc:
            continue
        if proc in SUSPICIOUS_PROCESSES:
            host = _get_first(row, ["host", "hostname", "device"], default="unknown")
            findings.append({
                "rule": "suspicious_process",
                "etype": "host",
                "entity": host,
                "score": 2.5,
                "event": row,
            })
    return findings

def rule_rare_destinations(net_rows, min_count=1):
    findings = []
    dests = Counter()
    for row in net_rows or []:
        dest = _get_first(row, ["dest_ip", "dst_ip", "destination", "domain"], default=None)
        if not dest:
            continue
        dests[dest] += 1
    for row in net_rows or []:
        dest = _get_first(row, ["dest_ip", "dst_ip", "destination", "domain"], default=None)
        if not dest:
            continue
        if dests[dest] <= min_count:
            src = _get_first(row, ["src_ip", "source_ip", "ip"], default="unknown")
            findings.append({
                "rule": "rare_destination",
                "etype": "dest",
                "entity": dest,
                "score": 1.5,
                "event": {
                    "src": src,
                    "dest": dest,
                },
            })
    return findings
