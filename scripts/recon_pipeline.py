#!/usr/bin/env python3
import json
import subprocess
import sys
import logging
from datetime import datetime
from pathlib import Path
import requests
import sqlite3

BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "config" / "config.json"
OUTPUT_DIR = BASE_DIR / "output"
HTML_DIR = OUTPUT_DIR / "html"
JSON_DIR = OUTPUT_DIR / "json"
SCREENSHOTS_DIR = OUTPUT_DIR / "screenshots"
LOGS_DIR = OUTPUT_DIR / "logs"
HTTPX_PATH = Path.home() / "go/bin/httpx"

class ReconPipeline:
    def __init__(self, target):
        self.target = target
        self.domain = target.strip("/")
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = OUTPUT_DIR / f"{self.domain}_{self.timestamp}"
        
        for d in [self.session_dir, HTML_DIR, JSON_DIR, SCREENSHOTS_DIR, LOGS_DIR]:
            d.mkdir(parents=True, exist_ok=True)
        
        self.subs_file = self.session_dir / "subdomains.txt"
        self.resolved_file = self.session_dir / "resolved.txt"
        self.clean_file = self.session_dir / "domains_clean.txt"
        self.alive_file = self.session_dir / "alive.json"
        self.urls_file = self.session_dir / "urls.txt"
        self.vulns_file = self.session_dir / "vulnerabilities.json"
        self.report_html = HTML_DIR / f"report_{self.domain}_{self.timestamp}.html"
        self.report_json = JSON_DIR / f"report_{self.domain}_{self.timestamp}.json"
        self.log_file = LOGS_DIR / f"pipeline_{self.timestamp}.log"
        self.screenshot_dir = SCREENSHOTS_DIR / f"{self.domain}_{self.timestamp}"
        
        self.setup_logging()
        self.load_config()
        self.history_db = OUTPUT_DIR / "history.db"
        self.init_database()
        
    def setup_logging(self):
        handlers = [logging.FileHandler(self.log_file), logging.StreamHandler(sys.stdout)]
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=handlers)
        self.log = logging.getLogger(__name__)
        
    def load_config(self):
        try:
            with open(CONFIG_FILE) as f:
                self.config = json.load(f)
        except:
            self.config = {"telegram": {"enabled": False}}
    
    def init_database(self):
        conn = sqlite3.connect(self.history_db)
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS subdomains (domain TEXT, subdomain TEXT, first_seen TEXT, last_seen TEXT, UNIQUE(domain, subdomain))""")
        conn.commit()
        conn.close()
    
    def run_cmd(self, cmd, timeout=120):
        self.log.info(f"CMD: {cmd[:100]}...")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stderr
        except subprocess.TimeoutExpired:
            self.log.warning(f"Timeout después de {timeout}s")
            return False, "Timeout"
        except Exception as e:
            return False, str(e)
    
    def ensure_nuclei_templates(self):
        """Verifica que existan los templates de Nuclei, si no los descarga automáticamente"""
        templates_path = Path.home() / "nuclei-templates"
        
        if not templates_path.exists():
            self.log.info("[*] Descargando templates de Nuclei por primera vez...")
            self.log.info("[*] Esto puede tomar varios minutos...")
            cmd = "nuclei -update-templates"
            success, _ = self.run_cmd(cmd, timeout=600)
            if success:
                self.log.info("✅ Templates de Nuclei instalados correctamente")
                return True
            else:
                self.log.warning("⚠️ No se pudieron descargar los templates")
                self.log.warning("⚠️ Puedes instalarlos manualmente con: nuclei -update-templates")
                return False
        else:
            self.log.info(f"✅ Templates de Nuclei encontrados en: {templates_path}")
            return True
    
    def run_subfinder(self):
        self.log.info("[1/5] Subfinder...")
        cmd = f"subfinder -d {self.domain} -o {self.subs_file} -silent"
        success, _ = self.run_cmd(cmd, timeout=90)
        if success and self.subs_file.exists():
            count = len(open(self.subs_file).readlines())
            self.log.info(f"✅ {count} subdominios")
            return True
        return False
    
    def run_dnsx(self):
        self.log.info("[2/5] DNSx...")
        cmd = f"dnsx -l {self.subs_file} -a -resp -silent -o {self.resolved_file}"
        success, _ = self.run_cmd(cmd, timeout=90)
        if success and self.resolved_file.exists():
            clean = []
            with open(self.resolved_file) as f:
                for line in f:
                    if line.strip():
                        clean.append(line.split()[0])
            with open(self.clean_file, 'w') as f:
                f.write('\n'.join(clean))
            self.log.info(f"✅ {len(clean)} resueltos")
            return True
        return False
    
    def run_httpx(self):
        self.log.info("[3/5] HTTPx...")
        if not self.clean_file.exists():
            return False
        cmd = f"cat {self.clean_file} | {HTTPX_PATH} -json -silent -status-code -title -tech-detect -follow-redirects -timeout 5 -threads 100 > {self.alive_file}"
        success, _ = self.run_cmd(cmd, timeout=90)
        if success and self.alive_file.exists():
            count = len(open(self.alive_file).readlines())
            self.log.info(f"✅ {count} hosts activos")
            urls = []
            with open(self.alive_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            urls.append(data['url'])
                    except:
                        pass
            with open(self.urls_file, 'w') as f:
                f.write('\n'.join(urls))
            return True
        return False
    
    def run_gowitness(self):
        self.log.info("[4/5] GoWitness...")
        if not self.urls_file.exists() or self.urls_file.stat().st_size == 0:
            self.log.warning("No URLs")
            return False
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        cmd = f"gowitness scan file -f {self.urls_file} -s {self.screenshot_dir} --threads 10 --timeout 8 --write-none"
        success, _ = self.run_cmd(cmd, timeout=180)
        if self.screenshot_dir.exists():
            count = len(list(self.screenshot_dir.glob("*.jpeg"))) + len(list(self.screenshot_dir.glob("*.png")))
            self.log.info(f"✅ Screenshots: {self.screenshot_dir} ({count} capturas)")
            return True
        self.log.info(f"✅ Screenshots: {self.screenshot_dir}")
        return True

    def run_nuclei(self):
        self.log.info("[5/5] Nuclei...")
        if not self.urls_file.exists():
            return False
        
        # Asegurar que los templates existen
        self.ensure_nuclei_templates()
        
        cmd = f"nuclei -l {self.urls_file} -json -silent -severity critical,high,medium -o {self.vulns_file} -timeout 5 -c 30 -stats"
        success, _ = self.run_cmd(cmd, timeout=180)
        if success and self.vulns_file.exists() and self.vulns_file.stat().st_size > 0:
            count = len(open(self.vulns_file).readlines())
            self.log.info(f"✅ {count} vulnerabilidades encontradas")
            return True
        self.log.info("✅ No se encontraron vulnerabilidades")
        return True
    
    def check_new_subdomains(self):
        if not self.subs_file.exists():
            return []
        with open(self.subs_file) as f:
            current = {line.strip() for line in f}
        conn = sqlite3.connect(self.history_db)
        cursor = conn.cursor()
        cursor.execute("SELECT subdomain FROM subdomains WHERE domain = ?", (self.domain,))
        known = {row[0] for row in cursor.fetchall()}
        new_subs = current - known
        now = datetime.now().isoformat()
        for sub in new_subs:
            cursor.execute("INSERT OR REPLACE INTO subdomains (domain, subdomain, first_seen, last_seen) VALUES (?, ?, ?, ?)", (self.domain, sub, now, now))
        conn.commit()
        conn.close()
        if new_subs:
            self.log.info(f"🎉 {len(new_subs)} nuevos subdominios")
        return new_subs
    
    def generate_html_report(self):
        self.log.info("Generando reporte HTML...")
        subdomains = [l.strip() for l in open(self.subs_file)] if self.subs_file.exists() else []
        alive_hosts = []
        if self.alive_file.exists():
            with open(self.alive_file) as f:
                for line in f:
                    try:
                        alive_hosts.append(json.loads(line))
                    except:
                        pass
        
        vulns = []
        if self.vulns_file.exists():
            with open(self.vulns_file) as f:
                for line in f:
                    try:
                        vulns.append(json.loads(line))
                    except:
                        pass
        
        screenshot_count = 0
        if self.screenshot_dir.exists():
            screenshot_count = len(list(self.screenshot_dir.glob("*.jpeg"))) + len(list(self.screenshot_dir.glob("*.png")))
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #007bff; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🎯 Reconnaissance Report: {self.domain}</h1>
    <p>Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="stats">
        <div class="stat-box"><div class="stat-number">{len(subdomains)}</div><div>Subdominios</div></div>
        <div class="stat-box"><div class="stat-number">{len(alive_hosts)}</div><div>Hosts Activos</div></div>
        <div class="stat-box"><div class="stat-number">{len(vulns)}</div><div>Vulnerabilidades</div></div>
        <div class="stat-box"><div class="stat-number">{screenshot_count}</div><div>Screenshots</div></div>
    </div>
    
    <h2>📋 Subdominios ({len(subdomains)})</h2>
    <table>
        <tr><th>#</th><th>Subdominio</th></tr>
        {''.join(f'<tr><td>{i+1}</td><td>{s}</td></tr>' for i, s in enumerate(subdomains[:100]))}
    </table>
    {f'<p>... y {len(subdomains)-100} más</p>' if len(subdomains) > 100 else ''}
    
    <h2>🌐 Hosts Activos ({len(alive_hosts)})</h2>
    <table>
        <tr><th>URL</th><th>Status</th><th>Título</th><th>Tecnologías</th></tr>
        {''.join(f'<tr><td>{h.get("url", "N/A")}</td><td>{h.get("status_code", "N/A")}</td><td>{h.get("title", "N/A")[:60]}</td><td>{", ".join(h.get("tech", []))}</td></tr>' for h in alive_hosts[:50])}
    </table>
    {f'<p>... y {len(alive_hosts)-50} más</p>' if len(alive_hosts) > 50 else ''}
    
    <h2>⚠️ Vulnerabilidades ({len(vulns)})</h2>
    </table>
        <tr><th>Severidad</th><th>Nombre</th><th>Host</th><th>Template</th></tr>
        {''.join(f'<tr><td class="severity-{v.get("info", {}).get("severity", "")}">{v.get("info", {}).get("severity", "N/A").upper()}</td><td>{v.get("info", {}).get("name", "N/A")[:80]}</td><td>{v.get("host", "N/A")}</td><td>{v.get("template-id", "N/A")}</td></tr>' for v in vulns[:30])}
    </table>
    
    <h2>📸 Screenshots</h2>
    <p>Capturas guardadas en: <code>{self.screenshot_dir}</code></p>
    <p>Total de capturas: {screenshot_count}</p>
</div>
</body>
</html>"""
        with open(self.report_html, 'w') as f:
            f.write(html)
        self.log.info(f"✅ Reporte HTML: {self.report_html}")
    
    def generate_json_report(self):
        self.log.info("Generando reporte JSON...")
        subdomains = [l.strip() for l in open(self.subs_file)] if self.subs_file.exists() else []
        alive_hosts = []
        if self.alive_file.exists():
            with open(self.alive_file) as f:
                for line in f:
                    try:
                        alive_hosts.append(json.loads(line))
                    except:
                        pass
        
        vulns = []
        if self.vulns_file.exists():
            with open(self.vulns_file) as f:
                for line in f:
                    try:
                        vulns.append(json.loads(line))
                    except:
                        pass
        
        data = {
            "target": self.domain,
            "timestamp": self.timestamp,
            "statistics": {
                "total_subdomains": len(subdomains),
                "alive_hosts": len(alive_hosts),
                "vulnerabilities": len(vulns)
            },
            "subdomains": subdomains,
            "alive_hosts": alive_hosts,
            "vulnerabilities": vulns
        }
        with open(self.report_json, 'w') as f:
            json.dump(data, f, indent=2)
        self.log.info(f"✅ Reporte JSON: {self.report_json}")
    
    def send_telegram(self, new_subs=None):
        tg = self.config.get('telegram', {})
        if not tg.get('enabled', False):
            return
        token = tg.get('bot_token')
        chat_id = tg.get('chat_id')
        if not token or token == "TU_BOT_TOKEN_AQUI":
            return
        subs = len(open(self.subs_file).readlines()) if self.subs_file.exists() else 0
        alive = len(open(self.alive_file).readlines()) if self.alive_file.exists() else 0
        new_count = len(new_subs) if new_subs else 0
        vulns = len(open(self.vulns_file).readlines()) if self.vulns_file.exists() else 0
        screenshot_count = len(list(self.screenshot_dir.glob("*.jpeg"))) + len(list(self.screenshot_dir.glob("*.png"))) if self.screenshot_dir.exists() else 0
        
        msg = f"""✅ *Recon completado: {self.domain}*

📊 *Resultados:*
• Subdominios totales: {subs}
• Hosts activos: {alive}
• Vulnerabilidades: {vulns}
• Nuevos subdominios: {new_count}
• Screenshots: {screenshot_count}

📁 *Archivos generados:*
• 📄 HTML: `{self.report_html}`
• 📋 JSON: `{self.report_json}`
• 📸 Screenshots: `{self.screenshot_dir}`"""
        
        if new_count > 0:
            msg += f"\n\n🎯 *Ejemplos nuevos subdominios:*\n"
            for sub in list(new_subs)[:5]:
                msg += f"• `{sub}`\n"
            if new_count > 5:
                msg += f"• *... y {new_count - 5} más*"
        
        try:
            requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json={'chat_id': chat_id, 'text': msg, 'parse_mode': 'Markdown'}, timeout=5)
            self.log.info("✅ Telegram enviado")
        except Exception as e:
            self.log.error(f"Telegram error: {e}")
    
    def run(self):
        start_time = datetime.now()
        self.log.info("="*60)
        self.log.info(f"🚀 Bug Bounty Recon Pipeline")
        self.log.info(f"📋 Target: {self.domain}")
        self.log.info(f"📁 Output: {self.session_dir}")
        self.log.info("="*60)
        
        if not self.run_subfinder():
            self.log.error("❌ Subfinder falló")
            return False
        
        if not self.run_dnsx():
            self.log.error("❌ DNSx falló")
            return False
        
        self.run_httpx()
        self.run_gowitness()
        self.run_nuclei()
        
        new_subs = self.check_new_subdomains()
        self.generate_html_report()
        self.generate_json_report()
        self.send_telegram(new_subs)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        self.log.info("="*60)
        self.log.info(f"✅ PIPELINE COMPLETADO en {elapsed:.1f} segundos")
        self.log.info(f"📊 Subdominios: {len(open(self.subs_file).readlines()) if self.subs_file.exists() else 0}")
        self.log.info(f"🌐 Hosts activos: {len(open(self.alive_file).readlines()) if self.alive_file.exists() else 0}")
        self.log.info(f"📸 Screenshots: {self.screenshot_dir}")
        self.log.info(f"📄 Reporte HTML: {self.report_html}")
        self.log.info(f"📋 Log: {self.log_file}")
        self.log.info("="*60)
        
        return True

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "tesla.com"
    ReconPipeline(target).run()
