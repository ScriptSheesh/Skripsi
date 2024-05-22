from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import pandas as pd
import sqlite3
import re
import requests
import tldextract
import urllib.parse
import whois
import datetime
from sklearn.feature_extraction import FeatureHasher
import logging
from joblib import load
from sklearn.feature_extraction import FeatureHasher

app = Flask(__name__)
app.config['DEBUG'] = True

pipeline = load('XGBoost.joblib')

def load_phishing_urls():
        try:
            df = pd.read_csv('normalized_DatasetUrl.csv', header=None, dtype=str, on_bad_lines='skip')
            urls = df[0].tolist()
            urls_normalized = [url.rstrip('/') for url in urls]
            return set(urls_normalized)
        except pd.errors.ParserError:
            print("Error parsing CSV file. Check the file format.")
            return set()

known_phishing_urls = load_phishing_urls()

class DatabaseManager:
    def __init__(self, db_name='messages.db'):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
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
                    url TEXT PRIMARY KEY,
                    phishing_result INTEGER,
                    last_reported DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    def get_db(self):
        if 'db' not in g:
            g.db = sqlite3.connect(self.db_name)
        return g.db

    def save_message_if_not_exists(self, sender_number, url):
        db = self.get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM messages WHERE message_body=?", (url,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, url))
            db.commit()

    def check_and_save(self, sender_number, url):
        cursor = self.get_db().cursor()
        cursor.execute("SELECT phishing_result FROM rulebased WHERE url=?", (url,))
        result = cursor.fetchone()
        if result:
            return result
        else:
            self.save_message_if_not_exists(sender_number, url)
            return None

class URLAnalyzer:
    @staticmethod
    def contains_url(message):
        try:
            parsed_url = urlparse(message)
            return parsed_url.scheme != '' and parsed_url.netloc != ''
        except Exception as e:
            logging.error(f"Failed to parse URL in contains_url: {e}")
            return False
        
    # @staticmethod
    # def get_ssl_version(url):
    #     try:
    #         hostname = urlparse(url).netloc
    #         context = ssl.create_default_context()
    #         with socket.create_connection((hostname, 443)) as sock:
    #             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
    #                 return ssock.version()
    #     except Exception as e:
    #         print(f"Error retrieving SSL version: {e}")
    #         return "Error: URL not found or SSL version could not be retrieved"

    @staticmethod
    def contains_special_characters(url):
        try:
            special_chars_count = url.count("=") + url.count("?") + url.count("%")
            return special_chars_count
        except Exception as e:
            logging.error(f"Error checking special characters in URL: {e}")
            return 0

    @staticmethod
    def calculate_domain_age(creation_date):
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Assuming the first item in the list is the correct creation date
        if creation_date:
            now = datetime.datetime.now()
            if isinstance(creation_date, datetime.datetime):
                domain_age_years = (now - creation_date).days // 365
                if domain_age_years < 1:
                    return "0.5"
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
        try:
            extracted = tldextract.extract(url)
            return extracted.suffix
        except Exception as e:
            logging.error(f"Error extracting TLD from {url}: {e}")
            return ""

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

    @staticmethod
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
    
    @staticmethod
    def count_iframes(url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(url, headers=headers, timeout=10)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            iframes = soup.find_all('iframe')
            return len(iframes)
        except Exception as e:
            logging.error(f"Error counting iframes in {url}: {e}")
            return 0
    
    @staticmethod
    def detect_obfuscated(url):
        try:
            decoded_url = urllib.parse.unquote(url)
            return 1 if url != decoded_url else 0
        except Exception as e:
            logging.error(f"Error detecting obfuscation in {url}: {e}")
            return 0
    
    @staticmethod
    def detect_url_redirect(url):
        try:
            response = requests.get(url, allow_redirects=False)
            if response.status_code in [301, 302]:
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
                    return True if match else False
        except Exception as e:
            logging.error(f"Error detecting URL redirects in {url}: {e}")
            return False

    @staticmethod
    def count_javascript_elements(url):
        try:
            response = requests.get(url)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = soup.find_all('script')
            return len(scripts)
        except Exception as e:
            logging.error(f"Error counting JavaScript elements in {url}: {e}")
            return 0
        
    @staticmethod
    def is_https(url):
        try:
            response = requests.get(url)
            return response.url.startswith('https')
        except Exception as e:
            logging.error(f"Error checking HTTPS status for {url}: {e}")
            return False
            
    @staticmethod
    def get_url_length(url):
        try:
            return len(url)
        except Exception as e:
            logging.error(f"Error getting URL length for {url}: {e}")
            return 0

    @staticmethod
    def has_url_title(url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(url, headers=headers, timeout=10)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            return 1 if title and title.text.strip() else 0
        except Exception as e:
            logging.error(f"Error checking for URL title in {url}: {e}")
            return 0

    @staticmethod
    def get_webpage_title(url):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                title_tag = soup.find('title')
                return title_tag.text.strip() if title_tag else "Title not found"
            else:
                return "Failed to retrieve content"
        except Exception as e:
            logging.error(f"Error retrieving webpage title for {url}: {e}")
            return "Error fetching title"

    @staticmethod
    def title_match_scoring(webpage_title, url):
        try:
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
            return url_title_match_score(t_set, root_domain)
        except Exception as e:
            logging.error(f"Error scoring title match for {url}: {e}")
            return 0

class WebhookHandler:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    @staticmethod
    @app.route("/webhook", methods=['POST'])
    def webhook():
        db_manager = DatabaseManager()
        handler = WebhookHandler(db_manager)
        message_body = request.values.get('Body', None)
        sender_number = request.values.get('From', None)
        
        twiml_response = MessagingResponse()
        
        if not message_body or not URLAnalyzer.contains_url(message_body):
            twiml_response.message("URL yang anda masukkan tidak valid. Silakan masukkan URL yang valid 🙁")  # Invalid URL message
            return str(twiml_response)
        
        twiml_response.message("Mohon tunggu sebentar, URL sedang diperika 😊")  # Add waiting message
        urls = [url.strip() for url in message_body.split(',')]
        response = handler.process_message(sender_number, urls)

        twiml_response.message(response)
        return str(twiml_response)

    def process_message(self, sender_number, urls):
        final_responses = ["🔍 Pemeriksaan Selesai 🔍\n -----------------------------"]
        for url in urls:
            if url.endswith('/'):
                url = url[:-1]
            
            # Check if URL is known phishing URL from CSV
            if url in known_phishing_urls:
                response_message = "URL ini ada di database kami dan merupakan phishing \n -----------------------------"
                phishing_chance = "Phishing"
            else:
                # Check the local database for previous analysis results
                phishing_result = self.db_manager.check_and_save(sender_number, url)
                if phishing_result:
                    phishing_chance = 'Phishing' if phishing_result[0] == 0 else 'Bukan sebuah phishing'
                    
                    response_message = f"{url} sesuai dengan hasil (URL telah dilaporkan sebelumnya)"
                else:
                    # URL not known and not previously analyzed, proceed with machine learning analysis
                    phishing_chance, response_message = self.analyze_url(url)
            
            final_responses.append(f"URL 🌐: {url}\nHasil 🚩: {phishing_chance}\nKemungkinan Phishing: {response_message}")
        return '\n'.join(final_responses)

    
    def analyze_url(self, url):
        try:
            # Feature extraction
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
            # Hashing the TLD feature
            hasher = FeatureHasher(n_features=10, input_type='string')
            hashed_features = hasher.transform(new_X['TLD'].apply(lambda x: [x])).toarray()
            hashed_feature_names = [f'TLD_hashed_{i}' for i in range(10)]
            new_X = pd.concat([new_X.drop('TLD', axis=1), pd.DataFrame(hashed_features, columns=hashed_feature_names, index=new_X.index)], axis=1)

            # Predicting phishing chance using the loaded ML pipeline
            predictions = pipeline.predict(new_X)
            phishing_chance = "Tinggi" if predictions[0] == 0 else "Rendah"
            rule_based_response = f"{'Bukan sebuah Phishing' if predictions[0] == 1 else 'Link Phishing'}"

            # Saving the result to the database
            db = self.db_manager.get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO rulebased (url, phishing_result) VALUES (?, ?) ON CONFLICT(url) DO UPDATE SET phishing_result=excluded.phishing_result", (url, phishing_chance))
            db.commit()

            return rule_based_response, phishing_chance
        except Exception as e:
            logging.error(f"Terjadi error dalam memeriksa {url}: {e}")
            return f"Terjadi error pada: {url}", "Tidak dapat menentukan hasil 😞"

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Starting application...")
    db_manager = DatabaseManager()
    db_manager.init_db()
    app.run(threaded=True)