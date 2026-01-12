# MINI-SEIM-SOC
Mini SIEM en Python pour SOC Analyst : analyse de logs, détection de brute force, accès à des fichiers sensibles et commandes suspectes.
from collections import defaultdict

FAILED_LIMIT = 5
failed_logins = defaultdict(int)

alerts = []

with open("logs.txt", "r") as logs:
    for line in logs:
        if "LOGIN FAILED" in line:
            user = line.split("user=")[1].split()[0]
            failed_logins[user] += 1

            if failed_logins[user] >= FAILED_LIMIT:
                alerts.append(f"[ALERT] Brute force détecté sur le compte {user}")

        if "COMMAND EXECUTED" in line:
            alerts.append("[ALERT] Commande système dangereuse détectée")

        if "/etc/passwd" in line:
            alerts.append("[ALERT] Accès à un fichier sensible détecté")

with open("alerts.txt", "w") as alert_file:
    for alert in alerts:
        alert_file.write(alert + "\n")

print("Analyse terminée. Alertes générées.")
