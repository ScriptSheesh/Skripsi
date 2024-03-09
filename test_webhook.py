from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from flask import Flask, request

app = Flask(__name__)

# Twilio Account SID and Auth Token
account_sid = 'AC9c03680e492c1a798656e19f72a66eb9'
auth_token = 'ebfc77c3e7e84d4d08c72b84f4ad4710'

# Create a Twilio client
client = Client(account_sid, auth_token)

# Route to handle incoming WhatsApp messages
@app.route("/webhook", methods=['POST'])
def webhook():
    message_body = request.values.get('Body', None)
    sender_number = request.values.get('From', None)

    # Process the incoming message
    response = process_message(message_body)

    # Send a response
    twiml_response = MessagingResponse()
    twiml_response.message(response)
    return str(twiml_response)

def process_message(message):
    # bot logic here
    return "Hello! This is your WhatsApp bot. You said: " + message

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
