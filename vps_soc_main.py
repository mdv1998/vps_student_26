from vps_soc_analyzer import aggregate_attacks, detect_brute_force


def run_pipeline(log_path: str) -> None:
    """Запускает полный конвейер анализа логов."""
    with open(log_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    attacks = aggregate_attacks(log_lines)
    suspicious_ips = detect_brute_force(attacks)

    print("=== Mini-SOC: SSH Brute-Force Analyzer ===")
    print()

    if not suspicious_ips:
        print("Подозрительных IP не обнаружено.")
        return

    print("Подозрительные IP:")

    for ip in sorted(suspicious_ips):
        print(f"{ip}: {attacks[ip]} атак")


if __name__ == "__main__":
    run_pipeline("/home/student/logs/auth.log")