import ssl
from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
import pandas as pd
import sqlite3
import re
import socket
import requests
import whois
import pycountry

app = Flask(__name__)

def init_db():
    with app.app_context():
        with sqlite3.connect('messages.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY,
                    sender_number TEXT,
                    message_body TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    count INTEGER DEFAULT 1
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rulebased (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    domain_age TEXT,
                    tld TEXT,
                    is_cyrillic INTEGER,
                    phishing_chance TEXT,
                    region TEXT,
                    isp TEXT
                )
            ''')
            conn.commit()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('messages.db')
    return g.db

def load_phishing_urls():
    try:
        df = pd.read_csv('normalized_DatasetUrl.csv', header=None, dtype=str, on_bad_lines='skip')
        return df[0].tolist()
    except pd.errors.ParserError:
        print("Error parsing CSV file. Check the file format.")
        return []

@app.route("/webhook", methods=['POST'])
def webhook():
    db = get_db()
    cursor = db.cursor()

    message_body = request.values.get('Body', None)
    sender_number = request.values.get('From', None)

    response = process_message(cursor, sender_number, message_body)

    cursor.close()

    twiml_response = MessagingResponse()
    twiml_response.message(response)
    return str(twiml_response)

def process_message(cursor, sender_number, message):
    if contains_url(message):
        phishing_urls = load_phishing_urls()
        if message in phishing_urls:
            list_based_response = "URL " + message + " terdeteksi merupakan phishing pada database kami.\n"
        else:
            save_message_if_not_exists(cursor, sender_number, message)
            cursor.execute("SELECT timestamp, count FROM messages WHERE message_body=?", (message,))
            result = cursor.fetchone()
            if result:
                timestamp, count = result
                cursor.execute("UPDATE messages SET timestamp=CURRENT_TIMESTAMP, count=? WHERE message_body=?", (count + 1, message))
                cursor.connection.commit()
                list_based_response = f"URL {message} tidak ditemukan dalam database phishing kami.\nTerakhir dilaporkan pada {timestamp} sebanyak {count} kali.\n"
            else:
                return "0"

        rule_based_response, phishing_chance = check_and_save_rulebased(message)
        combined_response = f"{list_based_response} {rule_based_response} Kemungkinan phishing 🚩: {phishing_chance}"
        return combined_response
    else:
        return message + " bukan sebuah URL valid, Silahkan berikan URL yang valid."
    
def contains_url(message):
    parsed_url = urlparse(message)
    return parsed_url.scheme != '' and parsed_url.netloc != ''

def check_and_save_rulebased(url):
    
    # Ada issue jika region hanya di define 1 saja maka akan ada error, namun jika di define [var], region = [value] maka issue clear
    var_null, region = get_domain_region(url)
    isp = get_isp(url)
    domain_age = "Kurang Dari Satu Tahun"  
    is_cyrillic = bool(re.search('[\u0400-\u04FF]', url))
    ssl_version = get_ssl_version(url)
    
    # Logic TLD masih bermasalah
    tld = url.split('.')[-1]
    common_tlds = ['com', 'org', 'net', 'co.id', 'ac.id', 'ru', 'ir', 'in', 'uk', 'au', 'de', 'ua'] # TLD masih bermasalah
    is_common_tld = tld in common_tlds    
    
    criteria_met = 3 - sum([is_common_tld, domain_age != "Kurang Dari Satu Tahun", not is_cyrillic])
    phishing_chance = "100%" if criteria_met == 3 else "66%" if criteria_met >= 1 else "unlikely"
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO rulebased (url, domain_age, tld, is_cyrillic, phishing_chance, region, isp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                   (url, domain_age, 'umum' if is_common_tld else 'tidak umum', 1 if is_cyrillic else 0, phishing_chance, region, isp))
    db.commit()

    rule_based_response = f"-----------------------\n 🔍 Hasil Analisa 🔍 \n -----------------------\n URL 🔗 : {url}\n Top Level Domain (TLD) 🌐: {'Umum' if is_common_tld else 'Tidak Umum'}\n Karakter Cyrillic 🆎 : {'Mengandung Karakter Cyrillic' if is_cyrillic else 'Tidak Mengandung Karakter Cyrillic'}\n Usia Domain⏳: {domain_age}\n Domain Region 🌍 : {region}\n ISP 💻 : {isp}\n SSL Version 🔒 : {ssl_version}\n" 
    return rule_based_response, phishing_chance

def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else "Unknown"
    except Exception as e:
        print(f"Error retrieving country name: {e}")
        return "Unknown"

def get_isp(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip_address = socket.gethostbyname(hostname)

        ip_info_response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        ip_info_data = ip_info_response.json()
        isp = ip_info_data.get('org', 'Unknown ISP')

        return isp if isp else "Unknown ISP"
    except Exception as e:
        print(f"Error retrieving ISP information: {e}")
        return "Unknown ISP"

def get_domain_region(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip_address = socket.gethostbyname(hostname)

        ip_info_response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        ip_info_data = ip_info_response.json()
        country_code = ip_info_data.get('country')

        domain_info = whois.whois(hostname)
        domain_country_code = domain_info.get('country')

        country_name = get_country_name(country_code)
        domain_region = get_country_name(domain_country_code)

        return country_name if country_name else "Unknown", domain_region if domain_region else "Unknown"
    except Exception as e:
        print(f"Error retrieving domain information: {e}")
        return "Unknown", "Unknown"
    
def get_ssl_version(url):
    try:
        hostname = url.split('/')[2] 
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version()
    except Exception as e:
        print(f"Error retrieving SSL version: {e}")
        return "Unknown"

def save_message_if_not_exists(cursor, sender_number, message):
    cursor.execute("SELECT id FROM messages WHERE message_body=?", (message,))
    result = cursor.fetchone()
    if not result:
        cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
        cursor.connection.commit()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
