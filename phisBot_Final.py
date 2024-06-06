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
import idna
from sklearn.feature_extraction import FeatureHasher
import logging
from joblib import load
from sklearn.feature_extraction import FeatureHasher

app = Flask(__name__)
app.config['DEBUG'] = True

pipeline = load('LightGBM_with_missParamLearn.joblib')


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
                CREATE TABLE IF NOT EXISTS final (
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
        punycode_url = URLAnalyzer.to_punycode(url)
        cursor.execute("SELECT id FROM messages WHERE message_body=?", (punycode_url,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, punycode_url))
        db.commit()

    def check_and_save(self, sender_number, url):
        punycode_url = URLAnalyzer.to_punycode(url)
        cursor = self.get_db().cursor()
        cursor.execute("SELECT phishing_result FROM final WHERE url=?", (punycode_url,))
        result = cursor.fetchone()
        if result:
            return result
        else:
            self.save_message_if_not_exists(sender_number, punycode_url)
            return None
    
    def save_phishing_result(self, url, result):
        punycode_url = URLAnalyzer.to_punycode(url)
        db = self.get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO final (url, phishing_result) VALUES (?, ?) ON CONFLICT(url) DO UPDATE SET phishing_result=excluded.phishing_result",
            (punycode_url, result))
        db.commit()


class URLAnalyzer:
    @staticmethod
    def contains_cyrillic(url):
        cyrillic_pattern = re.compile(r'[\u0400-\u04FF]')
        return bool(cyrillic_pattern.search(url))

    @staticmethod
    def to_punycode(url):
        try:
            parsed_url = urlparse(url)
            if any(ord(char) > 127 for char in parsed_url.netloc):
                netloc_punycode = idna.encode(parsed_url.netloc).decode('ascii')
                return parsed_url._replace(netloc=netloc_punycode).geturl()
            return url
        except Exception as e:
            logging.error(f"Error converting to punycode: {e}")
            return url

    @staticmethod
    def contains_url(message):
        try:
            parsed_url = urlparse(message)
            return parsed_url.scheme != '' and parsed_url.netloc != ''
        except Exception as e:
            logging.error(f"Failed to parse URL in contains_url: {e}")
            return False

    @staticmethod
    def contains_special_characters(url):
        try:
            special_chars_count = url.count("=") + url.count("?") + url.count("%")
            return special_chars_count
        except Exception as e:
            logging.error(f"Error checking special characters in URL: {e}")
            return -999

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
                return -999
        return -999

    @staticmethod
    def get_domain_age_from_url(url):
        try:
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            if w.creation_date is not None:
                return URLAnalyzer.calculate_domain_age(w.creation_date)
            else:
                return -999
        except Exception as e:
            print(f"Error retrieving WHOIS data for {url}: {e}")
            return -999

    @staticmethod
    def get_tld(url):
        try:
            extracted = tldextract.extract(url)
            return extracted.suffix
        except Exception as e:
            logging.error(f"Error extracting TLD from {url}: {e}")
            return "-999"

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
            return -999

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
            return -999

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
            return -999

    @staticmethod
    def detect_obfuscated(url):
        try:
            decoded_url = urllib.parse.unquote(url)
            return 1 if url != decoded_url else 0
        except Exception as e:
            logging.error(f"Error detecting obfuscation in {url}: {e}")
            return -999

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
            return -999

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
            return -999

    @staticmethod
    def is_https(url):
        try:
            response = requests.get(url)
            return response.url.startswith('https')
        except Exception as e:
            logging.error(f"Error checking HTTPS status for {url}: {e}")
            return -999

    @staticmethod
    def get_url_length(url):
        try:
            return len(url)
        except Exception as e:
            logging.error(f"Error getting URL length for {url}: {e}")
            return -999

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
            return -999
        
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
            t_set = webpage_title.lower().split()

            parsed_url = urlparse(url)
            root_domain = parsed_url.netloc.lower()
            root_domain = re.sub(r'^www.', '', root_domain)
            root_domain = root_domain.split('.')[0]

            if len(root_domain) > 0:
                base_score = 100 / len(root_domain)
            else:
                base_score = 0

            score = 0
            for element in t_set:
                if root_domain.find(element.lower()) >= 0:
                    n = len(element)
                    score += base_score * n
                    root_domain = root_domain.replace(element.lower(), "", 1)
                if score > 99.9:
                    score = 100
                    break

            return score
        except Exception as e:
            logging.error(f"Error scoring title match for {url}: {e}")
            return -999


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

        if message_body.lower() == 'bantuan':
            twiml_response.message(
                f"🔍 Informasi PhishBot 🔍\n\nPhishBot menggunakan 3 teknik utama dalam mendeteksi suatu URL phishing / tidak, yaitu:\n\n1. List-based\n2. Rule-based\n3. Learning-based\n\nDalam pendeteksian URL secara lebih dalam terdapat 3 aturan yang memiliki peran penting, yaitu:\n\n1. Penggunaan HTTPS pada suatu URL, hal tersebut menunjukan bahwa URL tersebut memiliki keamanan ekstra\n\n2. Jumlah JavaScript yang digunakan dalam suatu URL, bertujuan untuk mendeteksi aktivitas berbahaya yang dapat berjalan secara otomatis pada suatu website\n\n3. Usia dari suatu URL, akan memberikan indikasi semakin tua sebuah URL maka semakin dapat dipercaya\n\nSelalu waspada dan berhati-hati ya 😊\n\nKetik 'FAQ' / 'About Us' jika ingin tau lebih banyak (tanpa tanda kutip)")
            return str(twiml_response)

        if message_body.lower() == 'faq':
            twiml_response.message(
                f"""❓ FAQ PhishBot ❓\n\n1. Apa itu List Based? (ketik '1FAQ' tanpa tanda kutip)\n2. Apa itu Rule Based? (ketik '2FAQ' tanpa tanda kutip)\n3. Apa itu Learning Based? (ketik '3FAQ' tanpa tanda kutip)\n4. Apa itu Karakater Cyrillic? (ketik '4FAQ' tanpa tanda kutip) """)
            return str(twiml_response)

        if message_body.lower() == '1faq':
            twiml_response.message(
                f"""❓ FAQ PhishBot List Based ❓\n\nPendekatan List Based menggunakan daftar yang telah dibuat sebelumnya untuk membuat keputusan\n\nContoh: Jika anda belum terdaftar pada KPPS maka anda tidak boleh melakukan pencoblosan dalam pemilu""")
            return str(twiml_response)

        if message_body.lower() == '2faq':
            twiml_response.message(
                f"""❓ FAQ PhishBot Rule Based ❓\n\nPendekatan Rule Based menggunakan aturan 'jika ini maka itu' yang telah ditentukan untuk membuat keputusan\n\nContoh: Jika pendapatan seseorang lebih dari $50,000 dan tidak ada catatan kriminal, maka pinjaman disetujui. Jika tidak, pinjaman ditolak.""")
            return str(twiml_response)

        if message_body.lower() == '3faq':
            twiml_response.message(
                f"""❓ FAQ PhishBot Learning Based ❓\n\nPendekatan Learning Based menggunakan komputer untuk belajar dari data masa lalu dan membuat keputusan berdasarkan pola yang dipelajari\n\nContoh: Sistem belajar dari pembelian sebelumnya untuk merekomendasikan produk yang mungkin disukai pengguna.""")
            return str(twiml_response)

        if message_body.lower() == '4faq':
            cyrillicEX = "https://www.pаypal.com"
            realEX = "https://www.xn--pypal-4ve.com/"
            twiml_response.message(
                f"""❓ FAQ PhishBot Karakter Cyrillic ❓\n\nKemudian, sebuah URL dapat dipalsukan juga menggunakan karakter cyrillic untuk menyamarkan domain atau alamat URL yang sebenarnya\n\nSebagai contoh URL phishing yang menggunakan karakter cyrillic adalah: {cyrillicEX}\n\nPerhatikan bahwa karakter 'а' di dalam URL tersebut sebenarnya adalah karakter cyrillic, bukan karakter Latin 'a'. Bentuk asli dari URL di atas dapat dilihat seperti ini {realEX} \n\nHal ini bisa menjadi trik untuk menipu pengguna yang mungkin tidak memperhatikan perbedaannya""")
            return str(twiml_response)

        if message_body.lower() == 'about us':
            twiml_response.message(
                f"""👥 About Us 👥\n\nPhishBot ini merupakan pengembangan bot whatsapp untuk mendeteksi URL phishing yang dilakukan demi memenuhi program skripsi Strata-1 Universitas Bina Nusantara, yang dikerjakan oleh:\n\n1. Andika Kusriyanto\n2. Faiz Zhafran\n3. Leonhard Andrew\n\nTerimakasih telah membantu kami dalam pengembangan PhishBot 🙏""")
            return str(twiml_response)

        if not message_body or not URLAnalyzer.contains_url(message_body):
            urlEx = "https://example.com"
            twiml_response.message(
                f"Halo! Selamat datang di PhisBot. Phishbot adalah chatbot yang dapat membantu anda menganalisis URL yang valid seperti {urlEx}\npada kolom chat untuk menentukan apakah URL tersebut phishing atau tidak\n\nKemudian jika ingin mengetahui informasi singkat mengenai PhishBot dapat mengetikan 'BANTUAN' pada kolom chat\n\nTerimakasih telah menggunakan PhishBot 😊")
            return str(twiml_response)

        twiml_response.message("Terimakasih telah menggunakan PhishBot 😊")# Add waiting message
        urls = [url.strip() for url in message_body.split(',')]
        response = handler.process_message(sender_number, urls)

        twiml_response.message(response)
        return str(twiml_response)

    def process_message(self, sender_number, urls):
        final_responses = ["🔍 Pemeriksaan Selesai 🔍\n"]

        for url in urls:
            rule_based_response = ""
            response_message_csv = ""  # Initialize response_message for CSV
            response_message_db = ""  # Initialize response_message for database

            if URLAnalyzer.contains_cyrillic(url):
                punycode_url = URLAnalyzer.to_punycode(url)
                final_responses.append(f"⚠️ URL ini mengandung karakter Cyrillic, berikut URL aslinya:\n{punycode_url}\n")

            if url.endswith('/'):
                url = url[:-1]

            punycode_url = URLAnalyzer.to_punycode(url)

            # Check if URL is known phishing URL from CSV
            if punycode_url in known_phishing_urls:
                response_message_csv = "URL ini ada di database kami dan merupakan phishing \n\n"
                phishing_chance = "Phishing"
            else:
                # Check the local database for previous analysis results
                phishing_result = self.db_manager.check_and_save(sender_number, punycode_url)
                if phishing_result:
                    phishing_chance = 'Phishing' if phishing_result[0] == 0 else 'Bukan sebuah phishing'
                    response_message_db = f"URL telah dilaporkan sebelumnya"
                else:
                    # URL not known and not previously analyzed, proceed with machine learning analysis
                    rule_based_response, phishing_chance = self.analyze_url(url)
                    response_message_db = f"{rule_based_response}"

                    # Simpan hasil analisis machine learning di database
                    self.db_manager.save_phishing_result(url, 0 if phishing_chance == 'Tinggi' else 1)

            # Append the appropriate response message
            if response_message_csv:
                final_responses.append(
                    f"URL 🌐: {url}\nHasil Analisa🚩: {phishing_chance}\nKemungkinan Phishing: {response_message_csv}")
            else:
                final_responses.append(
                    f"URL 🌐: {url}\nHasil Analisa🚩: {response_message_db}\nKemungkinan Phishing: {phishing_chance}")

        return '\n'.join(final_responses)



    def analyze_url(self, url):
        try:
            # Feature extraction
            punycode_url = URLAnalyzer.to_punycode(url)  # Convert URL to punycode if necessary
            new_data_dict = {
                'TLD': [URLAnalyzer.get_tld(punycode_url)],
                'Domain_Age': [URLAnalyzer.get_domain_age_from_url(punycode_url)],
                'special_char': [URLAnalyzer.contains_special_characters(punycode_url)],
                'HasSubmitButton': [1 if URLAnalyzer.check_submit_button(punycode_url) else 0],
                'HasPasswordField': [1 if URLAnalyzer.check_password_field(punycode_url) else 0],
                'NoOfiFrame': [URLAnalyzer.count_iframes(punycode_url)],
                'NoOfJS': [URLAnalyzer.count_javascript_elements(punycode_url)],
                'IsHTTPS': [1 if URLAnalyzer.is_https(punycode_url) else 0],
                'URLLength': [URLAnalyzer.get_url_length(punycode_url)],
                'HasTitle': [URLAnalyzer.has_url_title(punycode_url)],
                'HasObfuscation': [URLAnalyzer.detect_obfuscated(punycode_url)],
                'NoOfURLRedirect': [URLAnalyzer.detect_url_redirect(punycode_url)],
                'URLTitleMatchScore': [URLAnalyzer.title_match_scoring(URLAnalyzer.get_webpage_title(punycode_url), punycode_url)]
            }
            new_X = pd.DataFrame(new_data_dict)
            # Hashing the TLD feature
            hasher = FeatureHasher(n_features=10, input_type='string')
            hashed_features = hasher.transform(new_X['TLD'].apply(lambda x: [x])).toarray()
            hashed_feature_names = [f'TLD_hashed_{i}' for i in range(10)]
            new_X = pd.concat([new_X.drop('TLD', axis=1),
                            pd.DataFrame(hashed_features, columns=hashed_feature_names, index=new_X.index)], axis=1)

            # Predicting phishing chance using the loaded ML pipeline
            predictions = pipeline.predict(new_X)
            phishing_chance = "Tinggi" if predictions[0] == 0 else "Rendah"
            rule_based_response = f"{'Link Phishing' if predictions[0] == 0 else 'Bukan sebuah Phishing'}"

            # Save the result to the database with the correct phishing status
            self.db_manager.save_phishing_result(url, 0 if predictions[0] == 0 else 1)

            return rule_based_response, phishing_chance
        except Exception as e:
            logging.error(f"Terjadi error dalam analisis {url}: {e}")
            return f"404 Error: {url}", "Tidak dapat menentukan hasil 😞"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Starting application...")
    db_manager = DatabaseManager()
    db_manager.init_db()
    app.run(threaded=True)