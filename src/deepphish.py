import email
from email import policy
from email.header import decode_header
import re
import json
import os
import requests
from bs4 import BeautifulSoup

class DeepPhish:
    def __init__(self, config_path="config/config.json", indicators_path="data/phishing_indicators.json"):
        self.config = self._load_config(config_path)
        self.phishing_indicators = self._load_indicators(indicators_path)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

    def _load_config(self, config_path):
        if not os.path.exists(config_path):
            print(f"[WARNING] Archivo de configuración no encontrado: {config_path}. Usando configuración por defecto.")
            return {"virustotal_api_key": None, "safe_domains": ["example.com", "legit.org"]}
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"[ERROR] Error al parsear {config_path}. Asegúrate de que sea un JSON válido.")
            return {"virustotal_api_key": None, "safe_domains": ["example.com", "legit.org"]}

    def _load_indicators(self, indicators_path):
        if not os.path.exists(indicators_path):
            print(f"[WARNING] Archivo de indicadores de phishing no encontrado: {indicators_path}. Usando indicadores vacíos.")
            return {"blacklisted_domains": [], "blacklisted_keywords": []}
        try:
            with open(indicators_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"[ERROR] Error al parsear {indicators_path}. Asegúrate de que sea un JSON válido.")
            return {"blacklisted_domains": [], "blacklisted_keywords": []}

    def _decode_header_str(header_value):
        decoded_headers = decode_header(header_value)
        decoded_str = ""
        for part, charset in decoded_headers:
            if isinstance(part, bytes):
                decoded_str += part.decode(charset or 'utf-8', errors='ignore')
            else:
                decoded_str += part
        return decoded_str

    def parse_email(self, raw_email):
        msg = email.message_from_string(raw_email, policy=policy.default)
        parsed_email = {
            "subject": self._decode_header_str(msg["Subject"]) if msg["Subject"] else "",
            "from": self._decode_header_str(msg["From"]) if msg["From"] else "",
            "to": self._decode_header_str(msg["To"]) if msg["To"] else "",
            "date": msg["Date"] if msg["Date"] else "",
            "body": "",
            "html_body": "",
            "urls": [],
            "attachments": []
        }

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition"))

                if ctype == "text/plain" and "attachment" not in cdispo:
                    parsed_email["body"] += part.get_payload(decode=True).decode(errors='ignore')
                elif ctype == "text/html" and "attachment" not in cdispo:
                    parsed_email["html_body"] += part.get_payload(decode=True).decode(errors='ignore')
                elif "attachment" in cdispo:
                    filename = part.get_filename()
                    if filename:
                        parsed_email["attachments"].append(filename)
        else:
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                parsed_email["body"] = msg.get_payload(decode=True).decode(errors='ignore')
            elif ctype == "text/html":
                parsed_email["html_body"] = msg.get_payload(decode=True).decode(errors='ignore')

        # Extract URLs from both plain text and HTML bodies
        urls_plain = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', parsed_email["body"])
        urls_html = re.findall(r'href=["\"](http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)["\"]', parsed_email["html_body"])
        parsed_email["urls"] = list(set(urls_plain + urls_html))

        return parsed_email

    def check_url_virustotal(self, url):
        api_key = self.config.get("virustotal_api_key")
        if not api_key:
            return {"status": "skipped", "reason": "VirusTotal API key no configurada"}

        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"url": url}
        try:
            # First, submit the URL for scanning
            submit_response = requests.post(vt_url, headers=headers, data=data)
            submit_response.raise_for_status()
            analysis_id = submit_response.json()["data"]["id"]

            # Then, retrieve the analysis report
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(10): # Retry a few times for analysis to complete
                time.sleep(5)
                report_response = requests.get(report_url, headers=headers)
                report_response.raise_for_status()
                report_data = report_response.json()
                if report_data["data"]["attributes"]["status"] == "completed":
                    stats = report_data["data"]["attributes"]["stats"]
                    return {"status": "completed", "malicious": stats["malicious"], "suspicious": stats["suspicious"], "undetected": stats["undetected"], "harmless": stats["harmless"], "details": report_data}
            return {"status": "timeout", "reason": "Análisis de VirusTotal no completado a tiempo"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "reason": f"Error al consultar VirusTotal: {e}"}
        except KeyError:
            return {"status": "error", "reason": "Respuesta inesperada de VirusTotal"}

    def analyze_email(self, raw_email_content):
        parsed_email = self.parse_email(raw_email_content)
        analysis_results = {
            "email_details": parsed_email,
            "phishing_score": 0,
            "flags": []
        }

        # Heuristic Analysis
        # 1. Check sender domain against blacklists/whitelists
        from_domain = parsed_email["from"].split("@")[-1].replace(">", "").strip()
        if from_domain in self.phishing_indicators["blacklisted_domains"]:
            analysis_results["phishing_score"] += 50
            analysis_results["flags"].append(f"Dominio del remitente en lista negra: {from_domain}")
        elif from_domain not in self.config["safe_domains"]:
            analysis_results["phishing_score"] += 10
            analysis_results["flags"].append(f"Dominio del remitente no en lista blanca: {from_domain}")

        # 2. Check subject and body for blacklisted keywords
        for keyword in self.phishing_indicators["blacklisted_keywords"]:
            if keyword.lower() in parsed_email["subject"].lower() or keyword.lower() in parsed_email["body"].lower():
                analysis_results["phishing_score"] += 20
                analysis_results["flags"].append(f"Palabra clave de phishing detectada: {keyword}")

        # 3. Check URLs
        url_analysis = []
        for url in parsed_email["urls"]:
            vt_result = self.check_url_virustotal(url)
            if vt_result and vt_result.get("malicious", 0) > 0:
                analysis_results["phishing_score"] += 40
                analysis_results["flags"].append(f"URL maliciosa detectada por VirusTotal: {url}")
            url_analysis.append({"url": url, "virustotal_result": vt_result})
        analysis_results["url_analysis"] = url_analysis

        # 4. Check for suspicious attachments (e.g., .exe, .zip, .js)
        suspicious_extensions = [".exe", ".zip", ".js", ".vbs", ".docm", ".xlsm"]
        for attachment in parsed_email["attachments"]:
            if any(attachment.lower().endswith(ext) for ext in suspicious_extensions):
                analysis_results["phishing_score"] += 30
                analysis_results["flags"].append(f"Adjunto con extensión sospechosa: {attachment}")

        # Determine final verdict
        if analysis_results["phishing_score"] >= 70:
            analysis_results["verdict"] = "Phishing de Alta Confianza"
        elif analysis_results["phishing_score"] >= 30:
            analysis_results["verdict"] = "Phishing Sospechoso"
        else:
            analysis_results["verdict"] = "No Phishing"

        return analysis_results

def main():
    print("### DeepPhish - Analizador de Correos Electrónicos de Phishing ###")
    deepphish = DeepPhish()

    # Example usage: read raw email content from a file or stdin
    if len(sys.argv) > 1:
        email_file_path = sys.argv[1]
        if not os.path.exists(email_file_path):
            print(f"[ERROR] Archivo de correo electrónico no encontrado: {email_file_path}")
            sys.exit(1)
        with open(email_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_email_content = f.read()
    else:
        print("[*] Por favor, pega el contenido RAW del correo electrónico y presiona Ctrl+D (o Ctrl+Z en Windows) cuando termines:")
        raw_email_content = sys.stdin.read()

    if not raw_email_content.strip():
        print("[ERROR] No se proporcionó contenido de correo electrónico.")
        sys.exit(1)

    analysis = deepphish.analyze_email(raw_email_content)

    print("\n--- Resultados del Análisis de DeepPhish ---")
    print(json.dumps(analysis, indent=4, ensure_ascii=False))

    # Save report
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/deepphish_report.json"
    with open(report_path, "w", encoding='utf-8') as f:
        json.dump(analysis, f, indent=4, ensure_ascii=False)
    print(f"[+] Reporte de análisis guardado en {report_path}")

if __name__ == "__main__":
    main()
