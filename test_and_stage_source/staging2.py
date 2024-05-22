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
import urllib.parse

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
                    has_submit_button INTEGER,
                    has_password_field INTEGER,
                    iframe_count INTEGER,
                    is_obfuscated INTEGER,
                    redirected_url TEXT,
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
        df = pd.read_csv('normalized_TestUrl.csv', header=None, dtype=str, on_bad_lines='skip')
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

def contains_special_characters(url):
    # Count specific special characters like "=", "?", and "%"
    special_chars_count = url.count("=") + url.count("?") + url.count("%")
    return special_chars_count

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
    
def detect_obfuscated(url):
    decoded_url = urllib.parse.unquote(url)
    if url != decoded_url:
        return 1  # Obfuscated characters detected
    else:
        return 0  # No obfuscated characters detected
    
def detect_url_redirect(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code == 301 or response.status_code == 302:
            redirected_url = response.headers['Location']
            return redirected_url
        else:
            html_code = response.text
            # Define regular expressions to search for URL redirection patterns
            patterns = [
                r'http-equiv\s*=\s*"refresh"\s*content\s*=\s*["\']\d+;\s*url\s*=\s*([^"\']+)["\']',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.replace\s*[(]["\']([^"\']+)["\'][)]',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'http\.open\s*[(][^,]+,\s*["\']([^"\']+)["\']'
            ]
            # Search for patterns in the HTML code
            for pattern in patterns:
                match = re.search(pattern, html_code)
                if match:
                    return match.group(1)  # Return the redirected URL if found
            return None  # Return None if no redirection patterns are found
    except Exception as e:
        print("Error:", e)
        return None

def process_message(cursor, sender_number, message):
    if contains_url(message):
        urls = [url.strip() for url in message.split(',')]
        responses = []

        for url in urls:
            db = get_db()
            cursor = db.cursor()

            # Check if URL has been previously analyzed
            cursor.execute("SELECT * FROM rulebased WHERE url=?", (url,))
            result = cursor.fetchone()

            if result:
                # URL already exists in rulebased table, return previous analysis results
                response_message = f"\nURL {url} telah dilaporkan sebelumnya dan memiliki kemungkinan sebagai URL phishing 🚩: {result[10]}"
                responses.append(response_message)
            else:
                # Conduct new analysis
                analysis_result, phishing_chance = check_and_save_rulebased(url)
                
                # Handle SSL error or any analysis failure explicitly
                if "Error: SSL version could not be retrieved" in analysis_result:
                    responses.append(f"Analysis for URL {url} stopped: SSL version could not be retrieved, indicating the URL might be unreachable.")
                elif "Error: URL analysis failed" in analysis_result:
                    responses.append(f"Analysis for URL {url} could not be completed due to an error.")
                else:
                    # New analysis was successful, check against known phishing URLs list
                    phishing_urls = load_phishing_urls()
                    if url in phishing_urls or url + '/' in phishing_urls:
                        list_based_response = f"\nURL {url} terdeteksi merupakan phishing pada database kami.\n"
                    else:
                        # Update messages database for non-listed URLs
                        save_message_if_not_exists(cursor, sender_number, url)
                        cursor.execute("SELECT timestamp, count FROM messages WHERE message_body=?", (url,))
                        result = cursor.fetchone()
                        if result:
                            timestamp, count = result
                            cursor.execute("UPDATE messages SET timestamp=CURRENT_TIMESTAMP, count=? WHERE message_body=?", (count + 1, url))
                            db.commit()
                            list_based_response = f"\nURL {url} tidak ditemukan dalam database phishing kami.\nTerakhir dilaporkan pada {timestamp} sebanyak {count} kali.\n"
                        else:
                            list_based_response = ""
                    
                    # Append the list-based response with rule-based analysis result
                    response_message = f"{list_based_response}{analysis_result} Kemungkinan phishing 🚩: {phishing_chance}"
                    responses.append(response_message)
                    
        return '\n'.join(responses)
    else:
        return "URL yang Anda masukkan tidak valid. Silakan masukkan URL yang valid."


def check_and_save_rulebased(url):
    try:
        ssl_version = get_ssl_version(url)
        tld = get_tld(url)
        # common_tlds = ['com', 'org', 'net', 'co.id', 'ac.id', 'ru', 'ir', 'in', 'uk', 'au', 'de', 'ua', 'edu']
        # is_common_tld = tld in common_tlds
        is_cyrillic = bool(re.search('[\u0400-\u04FF]', url))
        count_special_char = contains_special_characters(url)
        has_submit_button = check_submit_button(url)
        has_password_field = check_password_field(url)
        iframe_count = count_iframes(url)
        is_obfuscated = detect_obfuscated(url)
        redirected_url = detect_url_redirect(url) 

        criteria_met = sum([
            not is_cyrillic,
            count_special_char,
            not has_submit_button,
            not has_password_field,
            not iframe_count,
            is_obfuscated,
            count_special_char,
            1 if redirected_url else 0
        ])
        phishing_chance = "High" if criteria_met >= 7 else "Medium" if criteria_met >= 3 else "Low"

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO rulebased (url, tld, ssl_ver, is_cyrillic, has_submit_button, has_password_field, iframe_count, is_obfuscated, redirected_url,  phishing_chance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
            (url, tld, ssl_version, 1 if is_cyrillic else 0, 1 if has_submit_button else 0, 1 if has_password_field else 0, iframe_count, 1 if is_obfuscated else 0, '301' if redirected_url else '302', phishing_chance))
        db.commit()

        rule_based_response = rule_based_response = f"-----------------------\n 🔍 Hasil Analisa 🔍 \n -----------------------\n URL 🔗 : {url}\n Top Level Domain (TLD) 🌐: {tld}\n SSL Version 🔒 : {ssl_version}\n Karakter Cyrillic 🆎 : {'Mengandung Karakter Cyrillic' if is_cyrillic else 'Tidak Mengandung Karakter Cyrillic'}\n Terdapat Spesial Karakter❗: {count_special_char}\n Submit Button 📥: {'Terdeteksi' if has_submit_button else 'Tidak Terdeteksi'}\n Password Field 🔑: {'Terdeteksi' if has_password_field else 'Tidak Terdeteksi'}\n Iframe 🖼️: {iframe_count}\n Obsfuscated: {'Ya' if is_obfuscated else 'Tidak'}\n Redirect: {'Ya' if redirected_url else 'Tidak'}\n" 
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
