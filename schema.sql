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