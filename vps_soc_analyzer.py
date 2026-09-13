import re


def extract_ip(log_line: str) -> str | None:
    """Извлекает IP-адрес из строки неудачной SSH-аутентификации."""
    if "Failed password" in log_line or "Invalid user" in log_line:
        match = re.search(
            r"from\s+(\d{1,3}(?:\.\d{1,3}){3})",
            log_line,
        )

        if match:
            return match.group(1)

    return None


def aggregate_attacks(log_lines: list[str]) -> dict[str, int]:
    """Подсчитывает количество атак от каждого IP."""
    attacks = {}

    for line in log_lines:
        ip = extract_ip(line)

        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1

    return attacks


def detect_brute_force(
    attacks: dict[str, int],
    threshold: int = 5,
) -> set[str]:
    """Возвращает IP, количество атак которых достигло порога."""
    suspicious_ips = set()

    for ip, count in attacks.items():
        if count >= threshold:
            suspicious_ips.add(ip)

    return suspicious_ips