import datetime
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
import ssl

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

def contains_url(message):
    parsed_url = urlparse(message)
    return parsed_url.scheme != '' and parsed_url.netloc != ''

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
        return ip_info_data.get('org', 'Unknown ISP')
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
        country_code = ip_info_data.get('country', 'Unknown')
        return None, get_country_name(country_code)
    except Exception as e:
        print(f"Error retrieving domain region: {e}")
        return None, "Unknown"

def get_ssl_version(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version()
    except Exception as e:
        print(f"Error retrieving SSL version: {e}")
        return "Unknown"

def get_tld(url):
    complex_tlds = ['co.id', 'ac.id', 'co.uk']
    parts = url.split('.')
    for tld in complex_tlds:
        if url.endswith(tld):
            return tld
    return parts[-1]

def calculate_domain_age(creation_date):
    if creation_date:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime.datetime):
            now = datetime.datetime.now()
            domain_age_years = (now - creation_date).days // 365
            return f"{domain_age_years} years" if domain_age_years != 0 else "Less than a year"
    return "Unknown"

def process_message(cursor, sender_number, message):
    if contains_url(message):
        phishing_urls = load_phishing_urls()
        # Initialize list_based_response based on whether the URL is in phishing_urls
        if message in phishing_urls:
            list_based_response = "URL detected as phishing in our database.\n"
        else:
            list_based_response = "This is the first time this URL has been reported to us.\n"
            # Save the message if it's not recognized as phishing
            save_message_if_not_exists(cursor, sender_number, message)
            # You might want to fetch the last report time and count here if necessary

        # Call to check and save rule-based analysis
        rule_based_response, phishing_chance = check_and_save_rulebased(message)
        combined_response = f"{list_based_response}{rule_based_response} Phishing likelihood: {phishing_chance}"
        return combined_response
    else:
        return "The received message is not a valid URL. Please send a valid URL."


def check_and_save_rulebased(url):
    try:
        domain_name = urlparse(url).netloc
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date

        domain_age = calculate_domain_age(creation_date)
        _, region = get_domain_region(url)
        isp = get_isp(url)
        is_cyrillic = bool(re.search('[\u0400-\u04FF]', url))
        ssl_version = get_ssl_version(url)
        tld = get_tld(url)

        common_tlds = ['com', 'org', 'net', 'co.id', 'ac.id', 'ru', 'ir', 'in', 'uk', 'au', 'de', 'ua']
        is_common_tld = tld in common_tlds

        criteria_met = 3 - sum([is_common_tld, domain_age != "Unknown", not is_cyrillic])
        phishing_chance = "100%" if criteria_met == 3 else "66%" if criteria_met >= 1 else "unlikely"

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO rulebased (url, domain_age, tld, is_cyrillic, phishing_chance, region, isp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                       (url, domain_age, 'common' if is_common_tld else 'uncommon', 1 if is_cyrillic else 0, phishing_chance, region, isp))
        db.commit()

        rule_based_response = f"Analysis Results:\nURL: {url}\nTLD: {'Common' if is_common_tld else 'Uncommon'}\nContains Cyrillic: {'Yes' if is_cyrillic else 'No'}\nDomain Age: {domain_age}\nRegion: {region}\nISP: {isp}\nSSL Version: {ssl_version}\n"
        return rule_based_response, phishing_chance
    except Exception as e:
        print(f"An error occurred during rule-based analysis: {e}")
        return "An error occurred during processing. Unable to complete analysis.", "Error"

def save_message_if_not_exists(cursor, sender_number, message):
    cursor.execute("SELECT id FROM messages WHERE message_body=?", (message,))
    result = cursor.fetchone()
    if not result:
        cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
        cursor.connection.commit()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
