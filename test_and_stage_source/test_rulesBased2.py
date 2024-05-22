from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import pandas as pd
import sqlite3
import re
import socket
import ssl
import requests
import tldextract

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
                    tld TEXT,
                    ssl_ver TEXT,
                    is_cyrillic INTEGER,
                    phishing_chance TEXT
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
        urls = df[0].tolist()
        urls_with_slash = [url if url.endswith('/') else url + '/' for url in urls]
        return urls_with_slash
    
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
    extracted = tldextract.extract(url)
    return extracted.suffix

def check_submit_button(url):
    try:
        # Send a request to the URL and retrieve the HTML content
        response = requests.get(url)
        html_content = response.content
        
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check if any input element is a submit button
        submit_button = soup.find('input', {'type': 'submit'})
        
        # Check if any button element is a submit button
        if not submit_button:
            submit_button = soup.find('button', {'type': 'submit'})
        
        return submit_button is not None
    except Exception as e:
        print(f"Error checking for submit button: {e}")
        return False

    
def check_password_field(url):
    try:
        # Send a request to the URL and retrieve the HTML content
        response = requests.get(url)
        html_content = response.content
        
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check if a password field is present
        password_field = soup.find('input', {'type': 'password'})
        
        return password_field is not None
    except Exception as e:
        print(f"Error checking for password field: {e}")
        return False
    
def count_iframes(url):
    try:
        response = requests.get(url)
        html_content = response.content
        soup = BeautifulSoup(html_content, 'html.parser')
        iframes = soup.find_all('iframe')
        return len(iframes)
    except Exception as e:
        print(f"Error counting iframes: {e}")
        return 0

def process_message(cursor, sender_number, message):
    if contains_url(message):
        phishing_urls = load_phishing_urls()

        # Check if the input URL matches any variation in the phishing database
        if message in phishing_urls:
            list_based_response = f"URL " + message + " terdeteksi merupakan phishing pada database kami.\n"
        else:
            # Check if the input URL with a trailing slash matches any variation in the phishing database
            message_with_slash = message + '/'
            if message_with_slash in phishing_urls:
                list_based_response = f"URL " + message + " terdeteksi merupakan phishing pada database kami.\n"
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
                    list_based_response = "0"

        rule_based_response, phishing_chance = check_and_save_rulebased(message)
        iframe_count = count_iframes(message)
        if iframe_count > 0:
            rule_based_response += f" Jumlah Iframe 🖼️: {iframe_count}\n"
        combined_response = f"{list_based_response} {rule_based_response} Kemungkinan phishing 🚩: {phishing_chance}"
        return combined_response
    else:
        return message + " bukan sebuah URL valid, Silahkan masukan URL yang valid."

def check_and_save_rulebased(url):
    try:
        ssl_version = get_ssl_version(url)
        tld = get_tld(url)
        common_tlds = ['com', 'org', 'net', 'co.id', 'ac.id', 'ru', 'ir', 'in', 'uk', 'au', 'de', 'ua', 'edu']
        is_common_tld = tld in common_tlds
        is_cyrillic = bool(re.search('[\u0400-\u04FF]', url))
        contains_special_characters = bool(re.search(r'[0-9=\\?%]', url))
        has_submit_button = check_submit_button(url)
        has_password_field = check_password_field(url)
        iframe_count = count_iframes(url)

        criteria_met = 6 - sum([
            is_common_tld != "Unknown",
            not is_cyrillic,
            contains_special_characters,
            not has_submit_button,
            not has_password_field,
            not iframe_count
        ])
        phishing_chance = "100%" if criteria_met == 6 else "66%" if criteria_met >= 4 else "33%" if criteria_met >= 2 else "16%" if criteria_met >= 1 else "URL tidak terdeteksi phishing"

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO rulebased (url, tld, ssl_ver, is_cyrillic, phishing_chance) VALUES (?, ?, ?, ?, ?)", 
                       (url, 'common' if is_common_tld else 'uncommon', ssl_version, 1 if is_cyrillic else 0, phishing_chance))
        db.commit()

        rule_based_response = rule_based_response = f"-----------------------\n 🔍 Hasil Analisa 🔍 \n -----------------------\n URL 🔗 : {url}\n Top Level Domain (TLD) 🌐: {'Umum' if is_common_tld else 'Tidak Umum'}\n SSL Version 🔒 : {ssl_version}\n Karakter Cyrillic 🆎 : {'Mengandung Karakter Cyrillic' if is_cyrillic else 'Tidak Mengandung Karakter Cyrillic'}\n Terdapat Spesial Karakter❗: {'Ya' if contains_special_characters else 'Tidak'}\n Submit Button 📥: {'Terdeteksi' if has_submit_button else 'Tidak Terdeteksi'}\n Password Field 🔑: {'Terdeteksi' if has_password_field else 'Tidak Terdeteksi'}\n Iframe 🖼️: {'Terdeteksi' if iframe_count else 'Tidak Terdeteksi'}\n" 
        return rule_based_response, phishing_chance
    except Exception as e:
        print(f"Terjadi kesalahan dalam melakukan analisis: {e}")
        return "Error"

def save_message_if_not_exists(cursor, sender_number, message):
    cursor.execute("SELECT id FROM messages WHERE message_body=?", (message,))
    result = cursor.fetchone()
    if not result:
        cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
        cursor.connection.commit()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
