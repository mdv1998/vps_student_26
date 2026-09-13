from vps_soc_analyzer import aggregate_attacks, detect_brute_force

def run_pipeline(log_path: str) -> None:
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log_lines: list[str] = f.readlines()
    except FileNotFoundError:
        print(f"Ошибка: Файл {log_path} не найден.")
        return

    attacks: dict[str, int] = aggregate_attacks(log_lines)
    suspicious_ips: list[str] = detect_brute_force(attacks, threshold=5)

    print("=" * 40)
    print(" МИНИ-SOC: ОТЧЕТ ПО SSH BRUTE-FORCE ")
    print("=" * 40)
    if not suspicious_ips:
        print("Подозрительных IP-адресов не обнаружено.")
    else:
        print(f"Обнаружено опасных IP: {len(suspicious_ips)}\n")
        print(f"{'IP-адрес':<18} | {'Количество атак'}")
        print("-" * 35)
        for ip in suspicious_ips:
            print(f"{ip:<18} | {attacks[ip]}")
    print("=" * 40)

if __name__ == "__main__":
    run_pipeline("/home/student/logs/auth.log")
