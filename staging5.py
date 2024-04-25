from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
import pandas as pd
import sqlite3
import re
import socket
import ssl
import requests
import tldextract
import urllib.parse
import whois
import datetime

app = Flask(__name__)

class DatabaseManager:
    def __init__(self, db_name='messages.db'):
        self.db_name = db_name

    def init_db(self):
        with app.app_context():
            with sqlite3.connect(self.db_name) as conn:
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
                        domain_age INTEGER,
                        special_char INTEGER,
                        has_submit_button INTEGER,
                        has_password_field INTEGER,
                        iframe_count INTEGER,
                        js_count INTEGER,
                        is_https INTEGER,
                        get_url_length INTEGER,
                        Hastitle INTEGER,
                        is_obfuscated INTEGER,
                        redirected_url TEXT,
                        TitleScore INTEGER,
                        get_webpage_title TEXT,
                        phishing_chance TEXT,
                        ssl_ver TEXT,
                        is_cyrillic INTEGER
                    )
                ''')
                conn.commit()

    def get_db(self):
        if 'db' not in g:
            g.db = sqlite3.connect(self.db_name)
        return g.db

    def save_message_if_not_exists(self, sender_number, message):
        db = self.get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM messages WHERE message_body=?", (message,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
            db.commit()

class URLAnalyzer:
    @staticmethod
    def contains_url(message):
        parsed_url = urlparse(message)
        return parsed_url.scheme != '' and parsed_url.netloc != ''

    @staticmethod
    def get_ssl_version(url):
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.version()
        except Exception as e:
            print(f"Error retrieving SSL version: {e}")
            return "Error: URL not found or SSL version could not be retrieved"

    @staticmethod
    def contains_special_characters(url):
        special_chars_count = url.count("=") + url.count("?") + url.count("%")
        return special_chars_count

    @staticmethod
    def calculate_domain_age(creation_date):
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Assuming the first item in the list is the correct creation date
        if creation_date:
            now = datetime.datetime.now()
            if isinstance(creation_date, datetime.datetime):
                domain_age_years = (now - creation_date).days // 365
                if domain_age_years < 1:
                    return "Less than a year"
                else:
                    return f"{domain_age_years}"
            else:
                return "Invalid creation date format"
        return "Unknown"

    @staticmethod
    def get_domain_age_from_url(url):
        try:
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            if w.creation_date is not None:
                return URLAnalyzer.calculate_domain_age(w.creation_date)
            else:
                return "Creation date not found"
        except Exception as e:
            print(f"Error retrieving WHOIS data for {url}: {e}")
            return "Error"

    @staticmethod
    def get_tld(url):
        extracted = tldextract.extract(url)
        return extracted.suffix

    @staticmethod
    def check_submit_button(url):
        try:
            response = requests.get(url)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            submit_button = soup.find('input', {'type': 'submit'})
            
            if not submit_button:
                submit_button = soup.find('button', {'type': 'submit'})
            
            return submit_button is not None
        except Exception as e:
            print(f"Error checking for submit button: {e}")
            return False

    def check_password_field(url):
        try:
            response = requests.get(url)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            password_field = soup.find('input', {'type': 'password'})
            
            return password_field is not None
        except Exception as e:
            print(f"Error checking for password field: {e}")
            return False
    
        
    def count_iframes(url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        try:
            response = requests.get(url, headers=headers, timeout=10) 
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            iframes = soup.find_all('iframe')
            return len(iframes)
        except RequestException as e:
            print(f"Request exception occurred: {e}")
            return 0
        except Exception as e:
            print(f"General error occurred: {e}")
            return 0
    
    def detect_obfuscated(url):
        decoded_url = urllib.parse.unquote(url)
        if url != decoded_url:
            return 1 
        else:
            return 0 
    
    def detect_url_redirect(url):
        try:
            response = requests.get(url, allow_redirects=False)
            if response.status_code == 301 or response.status_code == 302:
                return True
            else:
                html_code = response.text
                patterns = [
                    r'http-equiv\s*=\s*"refresh"\s*content\s*=\s*["\']\d+;\s*url\s*=\s*([^"\']+)["\']',
                    r'window\.location\s*=\s*["\']([^"\']+)["\']',
                    r'window\.location\.replace\s*[(]["\']([^"\']+)["\'][)]',
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'http\.open\s*[(][^,]+,\s*["\']([^"\']+)["\']'
                ]
                for pattern in patterns:
                    match = re.search(pattern, html_code)
                    if match:
                        return 1 
                return 0
        except Exception as e:
            print("Error:", e)
            return 0

    def count_javascript_elements(url):
        try:
            response = requests.get(url)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = soup.find_all('script')
            return len(scripts)
        except Exception as e:
            print(f"Error counting JavaScript elements: {e}")
            return 0
        
    def is_https(url):
        try:
            response = requests.get(url)
            return response.url.startswith('https')
        except Exception as e:
            print(f"Error checking HTTPS: {e}")
            return False
            
    def get_url_length(url):
        return len(url)

    def has_url_title(url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            
            return 1 if title and title.text.strip() else 0
        except Exception:
            return 0 

    def get_webpage_title(url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                title_tag = soup.find('title')

                if title_tag:
                    return title_tag.text.strip()
                else:
                    return "Title not found" 
            else:
                return "Failed to retrieve content" 
        except requests.exceptions.RequestException as e:
            return f"Request error: {e}"

    def title_match_scoring(webpage_title, url):
        def url_title_match_score(t_set, txt_url):
            score = 0
            base_score = 100 / len(txt_url) if txt_url else 0
            for element in t_set:
                if txt_url.find(element.lower()) >= 0: 
                    n = len(element)
                    score += base_score * n
                    txt_url = txt_url.replace(element.lower(), "", 1)  
                if score > 99.9:
                    score = 100
                    break
            return score

        t_set = webpage_title.lower().split()  
        parsed_url = urlparse(url)
        root_domain = parsed_url.netloc.lower()  
        root_domain = re.sub(r'^www\.', '', root_domain) 
        root_domain = root_domain.split('.')[0] 
        score = url_title_match_score(t_set, root_domain)
        return score

class WebhookHandler:
    def __init__(self):
        self.db_manager = DatabaseManager()

    @staticmethod
    @app.route("/webhook", methods=['POST'])
    def webhook():
        db = DatabaseManager().get_db()
        cursor = db.cursor()

        message_body = request.values.get('Body', None)
        sender_number = request.values.get('From', None)

        response = WebhookHandler().process_message(cursor, sender_number, message_body, db)

        cursor.close()

        twiml_response = MessagingResponse()
        twiml_response.message(response)
        return str(twiml_response)

    
    def load_phishing_urls(self):
        try:
            df = pd.read_csv('normalized_DatasetUrl.csv', header=None, dtype=str, on_bad_lines='skip')
            urls = df[0].tolist()
            urls_with_slash = [url if url.endswith('/') else url + '/' for url in urls]
            return urls_with_slash
        except pd.errors.ParserError:
            print("Error parsing CSV file. Check the file format.")
            return []
        
    def process_message(self, cursor, sender_number, message, db):  # Add db as a parameter
        if URLAnalyzer.contains_url(message):
            urls = [url.strip() for url in message.split(',')]
        final_responses = []

        # Append the initial message separately
        final_responses.append("Mohon tunggu sebentar, URL sedang diperiksa...")

        for url in urls:
            phishing_urls = self.load_phishing_urls()  # Load phishing URLs from CSV file
            
            if url in phishing_urls or url + '/' in phishing_urls:
                list_based_response = f"\nURL {url} terdeteksi merupakan phishing pada database kami.\n"
                final_responses.append(list_based_response)
            else:
                cursor.execute("SELECT * FROM rulebased WHERE url=?", (url,))
                result = cursor.fetchone()

                if result:
                    response_message = f"\nURL {url} telah dilaporkan sebelumnya dan memiliki kemungkinan sebagai URL phishing 🚩: {result[10]}"
                    final_responses.append(response_message)
                else:
                    analysis_result, phishing_chance = self.check_and_save_rulebased(url)

                    if "Error: SSL version could not be retrieved" in analysis_result:
                        final_responses.append(f"Analysis for URL {url} stopped: SSL version could not be retrieved, indicating the URL might be unreachable.")
                    elif "Error: URL analysis failed" in analysis_result:
                        final_responses.append(f"Analysis for URL {url} could not be completed due to an error.")
                    else:
                        self.db_manager.save_message_if_not_exists(sender_number, url)
                        cursor.execute("SELECT timestamp, count FROM messages WHERE message_body=?", (url,))
                        result = cursor.fetchone()
                        if result:
                            timestamp, count = result
                            cursor.execute("UPDATE messages SET timestamp=CURRENT_TIMESTAMP, count=? WHERE message_body=?", (count + 1, url))
                            db.commit()  # Use db here instead of just commit()
                            list_based_response = f"\nURL {url} tidak ditemukan dalam database phishing kami.\nTerakhir dilaporkan pada {timestamp} sebanyak {count} kali.\n"
                        else:
                            list_based_response = ""

                        response_message = f"{list_based_response}{analysis_result}Kemungkinan phishing 🚩: {phishing_chance}"
                        final_responses.append(response_message)

            return '\n'.join(final_responses)  # Convert list of responses to a single string
        else:
            return "URL yang Anda masukkan tidak valid. Silakan masukkan URL yang valid."
     
    def check_and_save_rulebased(self, url):
        ssl_version = URLAnalyzer.get_ssl_version(url)
        if ssl_version == "Error: URL not found or SSL version could not be retrieved":
            return "Error: SSL version could not be retrieved, possibly due to the URL being unreachable.", "N/A"

        try:
            tld = URLAnalyzer.get_tld(url)
            is_cyrillic = bool(re.search('[\u0400-\u04FF]', url))
            special_char_count = URLAnalyzer.contains_special_characters(url)
            has_submit_button = URLAnalyzer.check_submit_button(url)
            has_password_field = URLAnalyzer.check_password_field(url)
            iframe_count = URLAnalyzer.count_iframes(url)
            is_obfuscated = URLAnalyzer.detect_obfuscated(url)
            redirected_url = URLAnalyzer.detect_url_redirect(url)
            js_count = URLAnalyzer.count_javascript_elements(url)
            https = URLAnalyzer.is_https(url)
            url_length = URLAnalyzer.get_url_length(url)
            has_title = URLAnalyzer.has_url_title(url)
            webpage_title = URLAnalyzer.get_webpage_title(url)
            title_score = URLAnalyzer.title_match_scoring(webpage_title, url)
            domain_age = URLAnalyzer.get_domain_age_from_url(url)
                
            criteria_met = sum([
                is_cyrillic,
                special_char_count,
                not has_submit_button,
                not has_password_field,
                iframe_count > 0,
                is_obfuscated,
                redirected_url,
                js_count > 10,
                not https,
                url_length > 34,
                not has_title,
                title_score
            ])
            
            phishing_chance = "High" if criteria_met >= 12 else "Medium" if criteria_met >= 5 else "Low"

            db = self.db_manager.get_db()
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO rulebased (
                    url, tld, domain_age, special_char,has_submit_button, 
                    has_password_field, iframe_count, js_count, is_https,
                    get_url_length, Hastitle, is_obfuscated, redirected_url, TitleScore, get_webpage_title, phishing_chance, ssl_ver, is_cyrillic) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url, tld, domain_age, special_char_count, 1 if has_submit_button else 0, 
                1 if has_password_field else 0, iframe_count, js_count, 1 if https else 0, 
                url_length, 1 if has_title else 0, 1 if is_obfuscated else 0, 
                redirected_url, title_score, webpage_title, phishing_chance, ssl_version, 1 if is_cyrillic else 0 
            ))
            db.commit()

            rule_based_response = f"-----------------------\n 🔍 Hasil Analisa 🔍 \n -----------------------\n URL 🔗 : {url}\n Top Level Domain (TLD) 🌐: {tld}\n Usia Domain (Tahun): {domain_age} tahun\n Terdapat Spesial Karakter❗: {special_char_count}\n Submit Button 📥: {'Terdeteksi' if has_submit_button else 'Tidak Terdeteksi'}\n Password Field 🔑: {'Terdeteksi' if has_password_field else 'Tidak Terdeteksi'}\n Iframe 🖼️: {iframe_count}\n JS: {'Terdeteksi' if js_count else 'Tidak Terdeteksi'}\n HTTPS: {'Ya' if https else 'Tidak'}\n UrlLength: {url_length}\n HasTitle: {'Terdeteksi' if has_title else 'Tidak Terdeteksi'}\n Obfuscated: {'Terdeteksi' if is_obfuscated else 'Tidak Terdeteksi'}\n RedirectURL: {'Terdeteksi' if redirected_url else 'Tidak Terdeteksi'}\n TitleScore: {title_score}\n Judul: {webpage_title}\n SSL Version 🔒 : {ssl_version}\n Karakter Cyrillic 🆎 : {'Mengandung Karakter Cyrillic' if is_cyrillic else 'Tidak Mengandung Karakter Cyrillic'}\n " 
            return rule_based_response, phishing_chance
        except Exception as e:
            print(f"Error during URL analysis: {e}")
            return "Error: URL analysis failed due to an exception: {str(e)}", "N/A"

if __name__ == "__main__":
    db_manager = DatabaseManager()
    db_manager.init_db()
    app.run(debug=True)
