import os
import time
import json
import requests
from bs4 import BeautifulSoup
import logging
import logging.handlers
import json.decoder
from datetime import datetime

log_dir = '/var/www/logs/cves'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_filename = datetime.now().strftime('%Y-%m-%d_%H-%M-%S') + '.log'
log_file_path = os.path.join(log_dir, log_filename)

# define o intervalo de tempo para girar o arquivo de log para a meia-noite todos os dias
#handler = logging.handlers.TimedRotatingFileHandler(log_file_path, when='midnight')
# define o limite máximo do arquivo de log para 10 MB e mantém no máximo 5 arquivos
handler = logging.handlers.RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=5)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])

NVD_API_KEY = os.getenv('NVD_API_KEY')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

def save_data(filename, data):
    logging.info('Salvando dados no arquivo {filename}')
    with open(filename, 'w') as f:
        json.dump({k: list(v) for k, v in data.items()}, f)




def load_data(filename):
    logging.info('Carregando dados do arquivo {filename}')
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            try:
                return {k: set(v) for k, v in json.load(f).items()}
            except json.decoder.JSONDecodeError:
                logging.info('Arquivo {filename} contém JSON inválido. Criando um novo arquivo.')
                return {}
    return {}



manufacturers = ['VMware', 'Arcserve', 'Sophos', 'Microsoft', 'Lenovo']
json_dir = './json_data'
if not os.path.exists(json_dir):
    os.makedirs(json_dir)

last_cves_file = os.path.join(json_dir, 'last_cves.json')
last_cves = load_data(last_cves_file) or {m: set() for m in manufacturers}


last_cve_result = {}


def search_cves():
    logging.info('Iniciando Pesquisa em {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    global last_cves, last_cve_result
    for m in manufacturers:
        url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={m}&resultsPerPage=2000'
        headers = {'User-Agent': 'Mozilla/5.0', 'API-Key': NVD_API_KEY}
        try:
            r = requests.get(url, headers=headers)
            r.raise_for_status()
            data = json.loads(r.content)
        except Exception as e:
            logging.error(f'Error: {e}')
            continue

        process_cves(data, m)
    logging.info('Verificação de novas (Criticas) CVEs atualizadas nos útlimos 15 dias concluída em {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))


def process_cves(data, m):
    if data['totalResults'] > 0:
        new_cves = set()
        for c in data['result']['CVE_Items']:
            id, date_str, desc, severity, refs, fix_url = extract_cve_details(c)
            if is_vulnerable(severity, date_str) and id not in last_cves[m]:
                new_cves.add(id)
                message = construct_message(m, id, desc, severity, refs, date_str, fix_url)
                send_telegram_message(message)
        update_last_cves(m, new_cves)
    else:
        logging.info('Não foram encontradas novas CVEs atualizadas nos útlimos 15 dias.')


def extract_cve_details(c):
        id = c['cve']['CVE_data_meta']['ID']
        date_str = c['lastModifiedDate']
        desc = c['cve']['description']['description_data'][0]['value']
        severity = 'unknown'
        refs = ''

        try:
            severity = c['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            pass

        if severity == 'CRITICAL':
            refs = '\n'.join(ref['url'] for ref in c['cve']['references']['reference_data'])

        return id, date_str, desc, severity, refs

def is_vulnerable(severity, date_str):
        return severity == 'CRITICAL' and (datetime.utcnow() - datetime.strptime(date_str, '%Y-%m-%dT%H:%MZ')).days <= 15

def update_last_cves(m, new_cves):
    if len(new_cves) == 0:
        message = f'Não foram encontradas novas CVEs (Criticas) atualizadas nos últimos 15 dias para {m}.'
        logging.info(message)
    else:
        last_cves[m] = last_cves[m].union(new_cves)
        save_data(last_cves_file, last_cves)


def extract_cve_details(c):
        id = c['cve']['CVE_data_meta']['ID']
        date_str = c['lastModifiedDate']
        desc = c['cve']['description']['description_data'][0]['value']
        severity = 'unknown'
        refs = ''
        fix_url = ''

        try:
            severity = c['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            pass

        if severity == 'CRITICAL':
            refs = '\n'.join(ref['url'] for ref in c['cve']['references']['reference_data'])
            fix_url = get_fix_url(c['cve']['references']['reference_data'])

        return id, date_str, desc, severity, refs, fix_url


def get_fix_url(reference_data):
        for ref in reference_data:
            if 'patch' in ref['url'].lower() or 'fix' in ref['url'].lower():
                return ref['url']
        return ''


def construct_message(m, id, desc, severity, refs, date_str, fix_url):
        message = f'Foi encontrada nova CVE (Critica) atualizada nos últimos 15 dias para {m}:\n\n{id}:\nDescrição: {desc}\nGravidade: {severity}\nReferências: {refs}\nÚltima modificação: {date_str}\n\n'
        if fix_url:
            message += f'Método de correção: {fix_url}\n\n'
        return message


def send_telegram_message(m):
        logging.info('Mensagem enviada ao Telegram em {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        r = requests.post(f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage', json={'chat_id': TELEGRAM_CHAT_ID, 'text': m})

#sent_recommendations = set()

def check_recommendations():
    recommendations_file = os.path.join(json_dir, 'recommendations.json')
    sent_recommendations = load_data(recommendations_file)
    url = "https://www.gov.br/ctir/pt-br/assuntos/alertas-e-recomendacoes/recomendacoes/2023"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")

    articles = soup.find_all("article", class_="entry")
    new_recommendations_found = False

    for article in articles:
        title = article.find("a").text.strip()
        description = article.find("p", class_="description").text.strip()
        recommendation_url = article.find("a")["href"]

        for manufacturer in manufacturers:
            if manufacturer.lower() in description.lower():
                if recommendation_url not in sent_recommendations:
                    message = f"{title}\n{description}\n{recommendation_url}"
                    send_telegram_message(message)
                    sent_recommendations[recommendation_url] = {'title': title, 'description': description}
                    new_recommendations_found = True
                    break

    if new_recommendations_found:
        logging.info("Novas recomendações encontradas e enviadas.")
        save_data(recommendations_file, sent_recommendations)
    else:
        logging.info("Nenhuma nova recomendação encontrada.")


while True:
        check_recommendations()
        search_cves()
        time.sleep(3600)

