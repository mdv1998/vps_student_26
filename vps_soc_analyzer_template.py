import re

def extract_ip(log_line: str) -> str | None:
    """Извлекает IPv4-адрес из строки лога SSH."""
    if "Failed password" in log_line or "Invalid user" in log_line:
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            return match.group(1)
    return None

def aggregate_attacks(log_lines: list[str]) -> dict[str, int]:
    """Считает количество атак для каждого IP-адреса."""
    attacks: dict[str, int] = {}
    for line in log_lines:
        ip: str | None = extract_ip(line)
        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """Псевдоним для aggregate_attacks."""
    return aggregate_attacks(log_lines)

def detect_brute_force(attacks: dict[str, int], threshold: int = 5) -> list[str]:
    """Возвращает список IP-адресов, где атак >= threshold."""
    bad_ips: list[str] = []
    for ip, count in attacks.items():
        if count >= threshold:
            bad_ips.append(ip)
    return bad_ips

def calculate_risk_score(failed_attempts: int, suspicious_paths: int = 0) -> str:
    """Рассчитывает уровень риска."""
    score = failed_attempts * 3 + suspicious_paths * 1
    if score >= 5:
        return "HIGH"
    elif score >= 1:
        return "MEDIUM"
    return "LOW"

def detect_suspicious_paths(log_line: str) -> bool:
    """Проверяет наличие опасных путей и векторов атак в строке лога."""
    patterns = [
        r'/etc/passwd', r'passwd', r'/admin', r'wp-admin', r'phpmyadmin', 
        r'\.\./', r'\.\.', r'SELECT', r'UNION', r'\.env', r'config',
        r'eval', r'exec', r'system', r'cmd', r'/bin/bash', r'/bin/sh'
    ]
    for pattern in patterns:
        if re.search(pattern, log_line, re.IGNORECASE):
            return True
    return False
