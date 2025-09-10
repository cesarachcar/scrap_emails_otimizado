import socket
import PyPDF2 as pyf
import pandas as pd
import certifi
import logging
import time
import sys
import re
from curl_cffi.requests.exceptions import CertificateVerifyError, RequestException
from selenium import webdriver
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from urllib.parse import urlparse
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization
from curl_cffi import requests as cureq
from io import BytesIO

logging.basicConfig(level=logging.DEBUG,  filename='otimizado.log', filemode='w',
            format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

#Configuração para também ver o log direto no terminal
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

class scrap_emails_otimizado:
    def __init__(self):
        self.dados_coletados = []
        self.counter = 0
        self.regex_email = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.status_codigo = 'indefinido'

    def _extracao_elsevier_wifi_institucional(self):
        try:
            servico = Service(ChromeDriverManager().install())
            navegador = webdriver.Chrome(service=servico)
            navegador.get(self.url_artigo)

            time.sleep(2)
            elementos_emails = navegador.find_elements(By.CSS_SELECTOR, 'svg.icon-envelope') #reconhece ícone de envelope

            for elemento in elementos_emails:
                elemento.click() #abre página lateral (que contém ícone de envelope)
                email = WebDriverWait(navegador, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'div.e-address .anchor-text'))) #reconhece email
                self.dados_coletados.append([email.text, 'elsevier', f'{self.counter + 1}° doi']) #armazena email reconhecido
                WebDriverWait(navegador, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'div.side-panel-header .icon.icon-cross'))).click() #fecha página lateral

            navegador.quit()
            logging.info('response2 (elsevier) aceito')
        except:
            logging.info('página não abriu ou não carregou')

    def _extracao_elsevier_wifi_residencial(self):
        try:
            servico = Service(ChromeDriverManager().install())
            navegador = webdriver.Chrome(service=servico)
            navegador.get(self.url_artigo)

            time.sleep(6)

            if navegador.find_element(By.ID, 'onetrust-banner-sdk'):
                navegador.find_element(By.ID, 'onetrust-accept-btn-handler').click()
                WebDriverWait(navegador, 10).until(
                    EC.element_to_be_clickable((By.CLASS_NAME, '_pendo-close-guide'))).click()

            time.sleep(2)
            elementos_emails = navegador.find_elements(By.CSS_SELECTOR,
                                                       'svg.icon.icon-envelope.react-xocs-author-icon.u-fill-grey8')

            for elemento in elementos_emails:
                elemento.click()
                email = WebDriverWait(navegador, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, 'div.e-address .anchor-text')))
                self.dados_coletados.append([email.text, 'elsevier', f'{self.counter + 1}° doi'])
                WebDriverWait(navegador, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, 'div.side-panel-header .icon.icon-cross'))).click()
            navegador.quit()
            logging.info('response2 (elsevier) aceito')
        except:
            logging.info('página não abriu ou não carregou')

    def _extracao_pdf(self):
        try:
            self.response2 = cureq.get(self.url_artigo, impersonate='chrome', verify=certifi.where())
            if self.response2.status_code == 200:
                logging.debug('response2 (pdf normal) aceito')
                if 'pdf' in self.response2.headers['Content-Type']:
                    self.pdf_file = BytesIO(self.response2.content)
                    self.reader = pyf.PdfReader(self.pdf_file)
                    self.counter_emails_adicionados = 0
                    for page in self.reader.pages:
                        text = page.extract_text() or ""
                        self.lista_emails = re.findall(self.regex_email, text)
                        for email in self.lista_emails:
                            self.dados_coletados.append([email, 'pdf normal', f'{self.counter + 1}° doi'])
                            self.counter_emails_adicionados += 1
                    logging.info(f'response2 (pdf normal) concluído - {self.counter_emails_adicionados} email(s) coletado(s)')
                else:
                    logging.info('response2 não é pdf')
            else:
                logging.info(f'response2 (pdf normal) negado: {self.response2.status_code}')
        except CertificateVerifyError as e:
            self._tratando_erro_curl60()
            if self.response2_tratado.status_code == 200:
                logging.info('response2 (pdf curl60) aceito')
                self.pdf_file = BytesIO(self.response2_tratado.content)
                self.reader = pyf.PdfReader(self.pdf_file)
                self.counter_emails_adicionados = 0
                for page in self.reader.pages:
                    text = page.extract_text() or ""
                    self.lista_emails = re.findall(self.regex_email, text)
                    for email in self.lista_emails:
                        self.dados_coletados.append([email, 'pdf curl60', f'{self.counter + 1}° doi'])
                        self.counter_emails_adicionados += 1
                logging.info(f'response2 (pdf curl60) concluído - {self.counter_emails_adicionados} email(s) coletado(s)')
            else:
                logging.error(f'response2_tratado (pdf) negado: {self.response2_tratado.status_code}')
        except RequestException as e:
            logging.error(f'Erro de requisição: {e}')
        except Exception as e:
            logging.error(f'Erro inesperado: {e}')

    def _tratando_erro_curl60(self):
        '''Trata o erro curl(60) de cadeias de certificado incompleta emitida pelo servidor'''
        parsed = urlparse((self.url_artigo))
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.output_pem = f'arquivos_pem/fullchain_{self.host}.pem'

        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        sock = socket.create_connection((self.host, self.port))
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(self.host.encode())
        conn.set_connect_state()
        conn.do_handshake()

        chain = conn.get_peer_cert_chain()
        with open(self.output_pem, "wb") as f:
            for cert in chain:
                f.write(cert.to_cryptography().public_bytes(serialization.Encoding.PEM))
        conn.close()
        sock.close()

        self.response2_tratado = cureq.get(self.url_artigo, impersonate='chrome', verify=self.output_pem, timeout=20,
                                           allow_redirects=True)

    def _extracao_pincipal(self):
        if 'Elsevier' in self.response1_json['publisher']:
            #self._extracao_elsevier_wifi_institucional()
            #self._extracao_elsevier_wifi_residencial()
            logging.info('response elsevier')
        else:
            self._extracao_pdf()

    def _salvar_emails(self):
        df = pd.DataFrame(self.dados_coletados, columns=['emails', 'origem', 'ordem doi'])
        df.to_excel(r'C:\Users\cesar\Downloads\emails_coletados.xlsx', index=False)
        #futuramente salvar mais informações (país, scopus ID para usar de índice, etc)

    def main(self, caminho_planilha_doi):
        '''Esta função prepara o link da requisição com base em cada doi da planilha'''
        inicio = time.time() #marcação de tempo de código
        self.email = 'cesar_achcar@hotmail.com'
        self.planilha_doi = pd.read_excel(caminho_planilha_doi)
        self.counter = 0
        for doi in self.planilha_doi['DOI']:
            if self.counter == 20:
                break
            inicio_loop = time.time()
            logging.info(f'começando {self.counter + 1}° doi')
            self.api_unpaywall = f'https://api.unpaywall.org/v2/{doi}?email={self.email}'
            try:
                self.response1 = cureq.get(self.api_unpaywall, impersonate='chrome', verify=certifi.where())
                self.response1_json = self.response1.json()
                # 2° requisição via funções
                if 'Elsevier' in self.response1_json['publisher']:
                    logging.info('response elsevier (pulou)')
                elif self.response1_json['best_oa_location']['url_for_pdf']:
                    self.url_artigo = self.response1_json['best_oa_location']['url_for_pdf']
                    self._extracao_pincipal()
                elif self.response1_json['best_oa_location']['url']:
                    self.url_artigo = self.response1_json['best_oa_location']['url']
                    self._extracao_pincipal()
            except Exception as e:
                logging.info(f'página vazia -> {e}')
            self.counter += 1
            fim_loop = time.time()
            duracao_loop = fim_loop - inicio_loop
            logging.info('{}° doi finalizado {:.2f} segundos ---------------------'.format(self.counter, duracao_loop))
        self._salvar_emails()
        fim = time.time() #marcação de tempo de código
        duracao = time.gmtime(fim - inicio)
        duracao_formatada = time.strftime("%H:%M:%S", duracao)
        logging.info(f'Tempo de código: {duracao_formatada}')









#programa
caminho_planilha_doi = r'C:\Users\cesar\Downloads\doi_codes.xlsx'
scrap_emails_otimizado().main(caminho_planilha_doi)
logging.info('código rodou com sucesso')
