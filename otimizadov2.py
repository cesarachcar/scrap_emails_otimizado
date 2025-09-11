import socket
import logging
import time
import sys
import re
from io import BytesIO
from urllib.parse import urlparse

import pandas as pd
import certifi
import PyPDF2 as pyf
from curl_cffi import requests as cureq
from curl_cffi.requests.exceptions import CertificateVerifyError, RequestException

from selenium import webdriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

# --- Logging Config ---
logging.basicConfig(level=logging.INFO, filename="otimizadov2.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s", encoding="utf-8")

# --- Logging Config do Console ---
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

class ScrapEmailsOtimizado:
    def __init__(self, email_registro_api: str = 'cesar_achcar@hotmail.com'):
        self.email_registro_api = email_registro_api
        self.dados_coletados = []
        self.counter = 0
        self.regex_email = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        self.response1_json = {}

    #Métodos de extração
    def _extracao_elsevier_institucional(self, url: str):
        '''Extração em ambiente institucional (rede da universidade)'''
        try:
            inicio_extracao_elsevier = time.time()
            servico = Service(ChromeDriverManager().install())
            navegador = webdriver.Chrome(service=servico)
            navegador.get(url)

            time.sleep(2)
            elementos_emails = navegador.find_elements(By.CSS_SELECTOR, "svg.icon-envelope")

            self._coletar_emails_elsevier(navegador, elementos_emails, origem="elsevier institucional")
            navegador.quit()
            fim_extracao_elsevier = time.time()
            logging.info('Extração Elsevier institucional concluída - {:.2f} s'.format(inicio_extracao_elsevier - fim_extracao_elsevier))
        except Exception as e:
            logging.error(f"Erro na extração Elsevier institucional: {e}", exc_info=True)

    def _extracao_elsevier_residencial(self, url: str):
        """Extração em ambiente residencial (com cookies/popup)."""
        try:
            inicio_extracao_elsevier = time.time()
            servico = Service(ChromeDriverManager().install())
            navegador = webdriver.Chrome(service=servico)
            navegador.get(url)

            time.sleep(6)
            # Aceita cookies se existir banner
            try:
                if navegador.find_element(By.ID, "onetrust-banner-sdk"):
                    navegador.find_element(By.ID, "onetrust-accept-btn-handler").click()
                    WebDriverWait(navegador, 10).until(
                        EC.element_to_be_clickable((By.CLASS_NAME, "_pendo-close-guide"))
                    ).click()
            except Exception:
                logging.info("Banner de cookies/popup não encontrado.")

            elementos_emails = navegador.find_elements(
                By.CSS_SELECTOR,
                "svg.icon.icon-envelope.react-xocs-author-icon.u-fill-grey8"
            )

            self._coletar_emails_elsevier(navegador, elementos_emails, origem="elsevier residencial")
            navegador.quit()
            fim_extracao_elsevier = time.time()
            logging.info('Extração Elsevier residencial concluída - {:.2f}'.format(inicio_extracao_elsevier - fim_extracao_elsevier))
        except Exception as e:
            logging.error(f"Erro na extração Elsevier residencial: {e}", exc_info=True)

    def _coletar_emails_elsevier(self, navegador, elementos, origem="elsevier"):
        """Ações comuns de clicar envelope → capturar e-mail → fechar painel (serve para institucional e residencial)"""
        for elemento in elementos:
            elemento.click()
            email_elem = WebDriverWait(navegador, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "div.e-address .anchor-text"))
            )
            self.dados_coletados.append([email_elem.text, origem, f"{self.counter + 1}° doi"])
            WebDriverWait(navegador, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "div.side-panel-header .icon.icon-cross"))
            ).click()

    def _processar_pdf(self, content: bytes, origem: str):
        """Processa PDF anteriormente baixado e extrai e-mails via regex."""
        pdf_file = BytesIO(content)
        reader = pyf.PdfReader(pdf_file)
        emails_encontrados = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            for email in re.findall(self.regex_email, text):
                self.dados_coletados.append([email, origem, f"{self.counter + 1}° doi"])
                emails_encontrados += 1
        logging.info(f"Extração PDF ({origem}) concluída - {emails_encontrados} e-mails.")

    def _extracao_pdf(self, url: str):
        """Baixa artigo PDF e extrai e-mails (com tratamento de certificados curl(60))."""
        try:
            response = cureq.get(url, impersonate="chrome", verify=certifi.where())
            if response.status_code == 200 and "pdf" in response.headers.get("Content-Type", ""):
                self._processar_pdf(response.content, "pdf normal")
            else:
                logging.info(f"Não é PDF ou status inválido: {response.status_code}")
        except CertificateVerifyError:
            logging.warning("Erro de certificado (curl 60), tentando corrigir...")
            response_corrigido = self._tratando_erro_curl60(url)
            if response_corrigido and response_corrigido.status_code == 200:
                self._processar_pdf(response_corrigido.content, "pdf curl60")
        except RequestException as e:
            logging.error(f"Erro de requisição PDF: {e}", exc_info=True)

    #Suporte SSL
    def _tratando_erro_curl60(self, url: str):
        """Resolve erro curl(60) baixando cadeia de certificados incompleta do servidor."""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        output_pem = f"arquivos_pem/fullchain_{host}.pem"

        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        sock = socket.create_connection((host, port))
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()

        chain = conn.get_peer_cert_chain()
        with open(output_pem, "wb") as f:
            for cert in chain:
                f.write(cert.to_cryptography().public_bytes(serialization.Encoding.PEM))

        conn.close()
        sock.close()

        return cureq.get(url, impersonate="chrome", verify=output_pem, timeout=20, allow_redirects=True)

    #Pipeline
    def _extracao_principal(self, url: str, ambiente="residencial", counter_loop=None):
        """Decide qual métoodo usar dependendo do ambiente configurado."""
        if "Elsevier" in self.response1_json.get("publisher", ""):
            if ambiente == "institucional":
                self._extracao_elsevier_institucional(url)
            else:
                self._extracao_elsevier_residencial(url)
        else:
            inicio_extracao_pdf = time.time()
            self._extracao_pdf(url)
            fim_extracao_pdf = time.time()
            logging.info('Finalizado {}° doi - {:.2f} s'.format(counter_loop, fim_extracao_pdf - inicio_extracao_pdf))

    def _salvar_emails(self, save_path: str):
        df = pd.DataFrame(self.dados_coletados, columns=["emails", "origem", "ordem doi"])
        df.to_excel(save_path, index=False)
        logging.info(f"E-mails salvos em {save_path}")

    def main(self, caminho_planilha_doi: str = r"C:\Users\cesar\Downloads\doi_codes.xlsx", save_path: str = r"C:\Users\cesar\Downloads\emails_coletados.xlsx"):
        """Percorre planilha de DOIs, consulta API Unpaywall e coleta e-mails."""
        inicio = time.time()
        planilha_doi = pd.read_excel(caminho_planilha_doi)

        for doi in planilha_doi["DOI"]:
            if self.counter >= 20:
                break
            ordem_doi_no_loop = self.counter + 1
            logging.info(f"Iniciando {ordem_doi_no_loop}° DOI: {doi}")

            try:
                api_unpaywall = f"https://api.unpaywall.org/v2/{doi}?email={self.email_registro_api}"
                response1 = cureq.get(api_unpaywall, impersonate="chrome", verify=certifi.where())
                self.response1_json = response1.json()

                best_loc = self.response1_json.get("best_oa_location", {})
                url_artigo = best_loc.get("url_for_pdf") or best_loc.get("url")
                if url_artigo:
                    self._extracao_principal(url_artigo, counter_loop=ordem_doi_no_loop)
            except Exception as e:
                logging.error(f"Erro processando DOI {doi}: {e}", exc_info=True)

            self.counter += 1

        self._salvar_emails(save_path)

        duracao = time.strftime("%H:%M:%S", time.gmtime(time.time() - inicio))
        logging.info(f"Tempo total de execução: {duracao}")

#Programa
if __name__ == "__main__":
    caminho_planilha_doi = r"C:\Users\cesar\Downloads\doi_codes.xlsx"
    save_path = r"C:\Users\cesar\Downloads\emails_coletados.xlsx"
    scrap = ScrapEmailsOtimizado()
    scrap.main(caminho_planilha_doi, save_path)
    logging.info("Código rodou com sucesso")
