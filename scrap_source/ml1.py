import pandas as pd
import sqlite3
import re
import ssl
import socket
import requests
from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from flask_executor import Executor
from sklearn.feature_extraction import FeatureHasher
from joblib import load
import tldextract
import urllib.parse
import whois
import datetime
from requests.exceptions import RequestException

# Load the saved pipeline
pipeline = load('XGBoost.joblib')

app = Flask(__name__)
executor = Executor(app)

class DatabaseManager:
    def __init__(self, db_name='messages.db'):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        with app.app_context():
            conn = sqlite3.connect(self.db_name)
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
            conn.close()

    def get_db(self):
        if 'db' not in g:
            g.db = sqlite3.connect(self.db_name)
        return g.db

    def save_message_if_not_exists(self, sender_number, message):
        with self.get_db() as db:
            cursor = db.cursor()
            cursor.execute("SELECT id FROM messages WHERE message_body=?", (message,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
                db.commit()

class URLAnalyzer:
    # (Include all static methods from the provided code snippet here)
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
    def __init__(self, app):
        self.app = app
        self.db_manager = DatabaseManager()
        self.app.route('/webhook', methods=['POST'])(self.webhook)

    def webhook(self):
        message_body = request.values.get('Body', None)
        sender_number = request.values.get('From', None)
        response = MessagingResponse()
        response.message("Please wait a moment, checking the URL...")

        if URLAnalyzer.contains_url(message_body):
            urls = [url.strip() for url in message_body.split(',')]
            results_response = self.process_message(sender_number, urls)
            response.message(results_response)
        else:
            response.message("Invalid URL provided. Please enter a valid URL.")
        return str(response)

    def process_message(self, sender_number, urls):
        final_responses = ["Please wait, checking the URLs..."]
        for url in urls:
            if url.endswith('/'):
                url = url[:-1]
            response_message, phishing_chance = self.analyze_url(url)
            self.db_manager.save_message_if_not_exists(sender_number, url)
            final_responses.append(f"URL: {url} | Phishing chance: {phishing_chance}\n{response_message}")
        return '\n'.join(final_responses)

    def analyze_url(self, url):
        # Machine Learning based prediction
        new_data_dict = {
            'TLD': [URLAnalyzer.get_tld(url)],
            'Domain_Age': [URLAnalyzer.get_domain_age_from_url(url)],
            'special_char': [URLAnalyzer.contains_special_characters(url)],
            'HasSubmitButton': [1 if URLAnalyzer.check_submit_button(url) else 0],
            'HasPasswordField': [1 if URLAnalyzer.check_password_field(url) else 0],
            'NoOfiFrame': [URLAnalyzer.count_iframes(url)],
            'NoOfJS': [URLAnalyzer.count_javascript_elements(url)],
            'IsHTTPS': [1 if URLAnalyzer.is_https(url) else 0],
            'URLLength': [URLAnalyzer.get_url_length(url)],
            'HasTitle': [URLAnalyzer.has_url_title(url)],
            'HasObfuscation': [URLAnalyzer.detect_obfuscated(url)],
            'NoOfURLRedirect': [URLAnalyzer.detect_url_redirect(url)],
            'URLTitleMatchScore': [URLAnalyzer.title_match_scoring(URLAnalyzer.get_webpage_title(url), url)]
        }
        new_X = pd.DataFrame(new_data_dict)

        if 'TLD' in new_X.columns:
            hasher = FeatureHasher(n_features=10, input_type='string')
            hashed_features = hasher.transform(new_X['TLD'].apply(lambda x: [x])).toarray()
            hashed_feature_names = [f'TLD_hashed_{i}' for i in range(10)]
            new_X = pd.concat([new_X.drop('TLD', axis=1), pd.DataFrame(hashed_features, columns=hashed_feature_names, index=new_X.index)], axis=1)

        predictions = pipeline.predict(new_X)
        phishing_chance = "Low" if predictions[0] == 1 else "High"
        rule_based_response = f"Analysis complete for URL: {url}\nPhishing Prediction: {'Not Phishing' if predictions[0] == 1 else 'Phishing'}"
        return rule_based_response, phishing_chance

if __name__ == "__main__":
    app = Flask(__name__)
    executor = Executor(app)
    webhook_handler = WebhookHandler(app)
    app.run(debug=True)

