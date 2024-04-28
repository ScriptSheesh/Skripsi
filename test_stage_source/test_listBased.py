import sqlite3
from flask import Flask, request, g
from twilio.twiml.messaging_response import MessagingResponse
from urllib.parse import urlparse
import pandas as pd

app = Flask(__name__)
# Function to initialize the database
def init_db():
    with app.app_context():
        with sqlite3.connect('messages.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                                id INTEGER PRIMARY KEY,
                                sender_number TEXT,
                                message_body TEXT,
                                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                                count INTEGER DEFAULT 1
                              )''')  
            conn.commit()

# Function to get the database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('messages.db')
    return g.db

# Load phishing URLs from CSV file into a list
def load_phishing_urls():
    try:
        df = pd.read_csv('normalized_DatasetUrl.csv', header=None, dtype=str, on_bad_lines='skip')
        return df[0].tolist() 
    except pd.errors.ParserError:
        print("Error parsing CSV file. Check the file format.")
        return []

# Route to handle incoming WhatsApp messages
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

# Logic to process the incoming message
def process_message(cursor, sender_number, message):
    # Check if the message contains a URL
    if contains_url(message):
        # Load phishing URLs
        phishing_urls = load_phishing_urls()
        # Check if the message is a phishing URL
        if message in phishing_urls:
            return "URL " + (message) +  " terdeteksi merupakan phishing pada database kami." 
        else:
            # Check if the message already exists in the database
            cursor.execute("SELECT timestamp, count FROM messages WHERE message_body=?", (message,))
            result = cursor.fetchone()
            if result:
                # If the message exists, update the timestamp and increment the count
                timestamp, count = result
                cursor.execute("UPDATE messages SET timestamp=CURRENT_TIMESTAMP, count=? WHERE message_body=?", (count + 1, message))
                cursor.connection.commit()
                return f"URL ini {message} terakhir dilaporkan pada {timestamp} sebanyak {count + 1}."
            else:
                # If the message does not exist, save it in the database
                save_message(cursor, sender_number, message)
                return "URL ini baru dilaporkan pada kami."
    else:
        return (message) + " bukan sebuah URL valid, Silahkan berikan URL yang valid."

def contains_url(message):
    # Parse the message to check if it contains a URL
    parsed_url = urlparse(message)
    return parsed_url.scheme != '' and parsed_url.netloc != ''

def save_message(cursor, sender_number, message):
    cursor.execute("INSERT INTO messages (sender_number, message_body) VALUES (?, ?)", (sender_number, message))
    cursor.connection.commit()

# Run the Flask app
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
