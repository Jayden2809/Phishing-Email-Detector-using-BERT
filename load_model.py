import os
import re
import torch
import logging
import requests
import json
import time
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from transformers import BertModel,BertTokenizerFast
from bs4 import BeautifulSoup
import base64
import mysql.connector
from datetime import datetime
import uuid
import sys

# Initialize Flask app with proper CORS configuration
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",  # You can restrict this to specific origins in production
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]
    }
})
logging.basicConfig(level=logging.INFO)

# Define the BERTClassifier class
class BERTClassifier(torch.nn.Module):
    def __init__(self, bert_model_name, num_classes):
        super(BERTClassifier, self).__init__()
        self.bert = BertModel.from_pretrained(bert_model_name)
        self.dropout = torch.nn.Dropout(0.1)
        self.fc = torch.nn.Linear(self.bert.config.hidden_size, num_classes)

    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output
        x = self.dropout(pooled_output)
        logits = self.fc(x)
        return logits

# Load the pre-trained BERT model and tokenizer
MODEL_PATH = "bert_email_classifier.pth"
TOKENIZER_PATH = "bert-base-uncased"  # Replace with your tokenizer
MAX_LENGTH = 128

# Initialize the model and tokenizer
try:
    model = BERTClassifier(bert_model_name=TOKENIZER_PATH, num_classes=2)
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at: {MODEL_PATH}")
    model.load_state_dict(torch.load(MODEL_PATH, map_location=torch.device("cpu"),weights_only=True))
    model.eval()

    tokenizer = BertTokenizerFast.from_pretrained(TOKENIZER_PATH)
    logging.info("Model and tokenizer loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load model or tokenizer: {e}")
    raise

# VirusTotal API functions
def scan_url(api_key, url):
    """Scan a URL using VirusTotal API."""
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key,
    }
    data = {
        "url": url
    }
    response = requests.post(url_scan_endpoint, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', {}).get('id')
    return None

def get_url_report(api_key, scan_id):
    """Get the report for a scanned URL."""
    url_report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        "x-apikey": api_key,
    }
    time.sleep(15)  # Wait for the report to be ready
    response = requests.get(url_report_endpoint, headers=headers)
    if response.status_code == 200:
        report = response.json()
        
        # Extract and print a summary of the report
        stats = report.get('data', {}).get('attributes', {}).get('stats', {})
        malicious_count = stats.get('malicious', 0)
        summary = f"{malicious_count} engines flagged this URL as malicious."
        
        # Check if the URL is flagged as malicious
        status = "malicious" if malicious_count > 0 else "clean"
        result = {"status": status, "summary": summary}
        
        # Print the report passed to the frontend
        print("URL Report:", result)
        
        return result
    
    return {"status": "error", "summary": "Error retrieving report"}

def scan_file(api_key, file_path):
    """Scan a file using VirusTotal API."""
    file_scan_endpoint = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": api_key,
    }
    with open(file_path, 'rb') as file:
        files = {"file": file}
        response = requests.post(file_scan_endpoint, headers=headers, files=files)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', {}).get('id')
    return None

def get_file_report(api_key, scan_id):
    """Get the report for a scanned file."""
    file_report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        "x-apikey": api_key,
    }
    time.sleep(15)  # Wait for the report to be ready
    response = requests.get(file_report_endpoint, headers=headers)
    if response.status_code == 200:
        report = response.json()
        
        # Extract and print a summary of the report
        stats = report.get('data', {}).get('attributes', {}).get('stats', {})
        malicious_count = stats.get('malicious', 0)
        summary = f"{malicious_count} engines flagged this file as malicious."
        
        # Check if the file is flagged as malicious
        status = "malicious" if malicious_count > 0 else "clean"
        result = {"status": status, "summary": summary}
        
        # Print the report passed to the frontend
        print("File Report:", result)
        
        return result
    
    return {"status": "error", "summary": "Error retrieving report"}

# Function for highlight text
def highlight_suspicious_sentences(email_text, model, tokenizer, threshold=0.7, max_length=128):
    # Parse email content to get clean text
    email_soup = BeautifulSoup(email_text, "html.parser")
    text_content = email_soup.get_text()

    # URL patterns for detection
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    shortened_url_pattern = r'\b(?:bit\.ly|t\.co|goo\.gl|tiny\.cc|tinyurl\.com)/\S+'

    # Split text into sentences using multiple delimiters: ., ，, ;, 。
    sentence_delimiters = r'[。；，.;]'
    sentences = [s.strip() for s in re.split(sentence_delimiters, text_content) if s.strip()]

    highlighted_sentences = []
    suspicious_sentences = []  # Track suspicious sentences for percentage calculation

    for sentence in sentences:
        # Find all URLs in the sentence
        urls = re.findall(url_pattern, sentence)
        shortened_urls = re.findall(shortened_url_pattern, sentence)
        all_urls = urls + shortened_urls

        # If the sentence is just a URL or only contains URLs with whitespace, skip highlighting
        cleaned_sentence = sentence
        for url in all_urls:
            cleaned_sentence = cleaned_sentence.replace(url, '').strip()
        
        if not cleaned_sentence:  # If nothing remains after removing URLs
            highlighted_sentences.append(sentence)
            continue

        # Create a clean version of the sentence for model prediction
        clean_sentence = sentence
        for url in all_urls:
            clean_sentence = clean_sentence.replace(url, '[URL]')

        # Tokenize the cleaned sentence
        encoding = tokenizer(
            clean_sentence,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=max_length
        )
        input_ids = encoding["input_ids"].to("cpu")
        attention_mask = encoding["attention_mask"].to("cpu")

        # Get prediction
        with torch.no_grad():
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs
            probabilities = torch.nn.functional.softmax(logits, dim=1)
            phishing_score = probabilities[0][1].item()  # Score for phishing class

        # Highlight the sentence if the phishing score exceeds the threshold
        if phishing_score > threshold:
            highlighted_sentence = f'<span style="background-color: rgba(255, 0, 0, 0.5); font-weight: bold;">{sentence}</span>'
            highlighted_sentences.append(highlighted_sentence)
            suspicious_sentences.append(sentence)
        else:
            highlighted_sentences.append(sentence)

    # Join sentences back together and rebuild the email content
    highlighted_text = " ".join(highlighted_sentences)
    email_soup.clear()
    email_soup.append(BeautifulSoup(highlighted_text, "html.parser"))

    return str(email_soup), suspicious_sentences

# Preprocess email text
def preprocess_email_text(email_text):
    from bs4 import BeautifulSoup
    import re
    
    # Remove HTML
    email_text = BeautifulSoup(email_text, "html.parser").get_text()
    
    # Handle URLs - Replace URLs with a standard token
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    email_text = re.sub(url_pattern, '[URL]', email_text)
    
    # Handle shortened URLs (e.g., bit.ly, t.co, etc.)
    shortened_url_pattern = r'\b(?:bit\.ly|t\.co|goo\.gl|tiny\.cc|tinyurl\.com)/\S+'
    email_text = re.sub(shortened_url_pattern, '[URL]', email_text)
    
    # Remove extra spaces/newlines
    email_text = re.sub(r"\s+", " ", email_text)
    
    return email_text.strip()

# Scan email content
def scan_email(email_text):
    preprocessed_text = preprocess_email_text(email_text)

    # Tokenize and prepare input
    encoding = tokenizer(
        preprocessed_text,
        return_tensors="pt",
        max_length=MAX_LENGTH,
        padding="max_length",
        truncation=True,
        return_offsets_mapping=True
    )
    input_ids = encoding["input_ids"]
    attention_mask = encoding["attention_mask"]
    offsets = encoding["offset_mapping"][0].cpu().numpy()

    # Perform inference
    with torch.no_grad():
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        logits = outputs[0].squeeze().cpu().numpy()
        probabilities = torch.nn.functional.softmax(torch.tensor(logits), dim=0)
        confidence, prediction = torch.max(probabilities, dim=0)

    # Get highlighted text and suspicious sentences
    highlighted_email, suspicious_sentences = highlight_suspicious_sentences(email_text, model, tokenizer)
    
    # Calculate confidence score (now just using model confidence)
    confidence_score = float(confidence.item() * 100)

    # Print the confidence
    logging.info("=== Scoring ===")
    logging.info(f"Model Confidence: {confidence_score:.2f}%")
    logging.info("=====================")

    return {
        "label": "Phishing Email" if prediction.item() == 1 else "Safe Email",
        "confidence": confidence_score,
        "highlighted_email": highlighted_email
    }

# Add VirusTotal API key
VIRUSTOTAL_API_KEY = "983d3a2406c224a7c38c6ca3c29c43ba3a1148d5d8bcb8d3943745e6a9097426"  # Replace with your actual API key

# Add database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Replace with your MySQL username
    'password': 'abc12345',  # Replace with your MySQL password
    'database': 'phishing',  # Your database name
    'raise_on_warnings': True
}

def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except mysql.connector.Error as err:
        logging.error(f"Database connection failed: {err}")
        return None

def check_email_exists(cursor, email_text, sender_email, subject, user_email):
    """Check if this email already exists in the database"""
    check_query = """
    SELECT id FROM phishing_emails 
    WHERE email_content = %s 
    AND sender_email = %s 
    AND subject = %s 
    AND user_email = %s
    """
    cursor.execute(check_query, (email_text, sender_email, subject, user_email))
    return cursor.fetchone() is not None

def store_phishing_email(email_data):
    connection = get_db_connection()
    if not connection:
        return False

    try:
        cursor = connection.cursor()
        
        # Ensure user exists in database
        user_email = email_data.get('user_email', '')
        user_type = email_data.get('user_type', 'guest')
        
        if not user_email:
            logging.error("No user email provided")
            return False
            
        if not register_user(user_email, user_type):
            logging.error("Failed to register/verify user")
            return False
        
        # Check if email already exists using the original HTML content
        if check_email_exists(
            cursor,
            email_data.get('original_email_text', ''),
            email_data.get('sender_email', ''),
            email_data.get('subject', ''),
            user_email
        ):
            logging.info("This email was already stored. Skipping...")
            return True

        received_time = None
        if email_data.get('received_time'):
            try:
                received_time = datetime.strptime(
                    email_data['received_time'].split('.')[0],
                    '%Y-%m-%dT%H:%M:%S'
                )
            except ValueError as e:
                logging.error(f"Date parsing error: {e}")
                received_time = datetime.now()
        
        # Store the original HTML content directly
        insert_query = """
        INSERT INTO phishing_emails (
            user_email,
            email_content,
            sender_email,
            subject,
            received_time,
            confidence_score,
            created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """
        
        data = (
            user_email,
            email_data['original_email_text'],  # Use the original HTML content
            email_data.get('sender_email', ''),
            email_data.get('subject', ''),
            received_time,
            email_data.get('confidence', 0.0)
        )
        
        cursor.execute(insert_query, data)
        connection.commit()
        
        logging.info(f"Successfully stored original email HTML for user: {user_email}")
        return True

    except mysql.connector.Error as err:
        logging.error(f"Failed to store phishing email: {err}")
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# Add these new endpoints for separate URL and attachment scanning
@app.route("/scan-urls", methods=["POST"])
def scan_urls_endpoint():
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        urls = request.json.get("urls", [])
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400

        url_results = []
        for url in urls:
            logging.info(f"Scanning URL: {url}")
            scan_id = scan_url(VIRUSTOTAL_API_KEY, url)
            
            # Validate scan_id
            if scan_id:
                report = get_url_report(VIRUSTOTAL_API_KEY, scan_id)
                if report:
                    url_results.append({
                        "url": url,
                        "status": "completed",
                        "report": report
                    })
                else:
                    url_results.append({
                        "url": url,
                        "status": "failed",
                        "report": {"error": "Invalid report data"}
                    })
            else:
                url_results.append({
                    "url": url,
                    "status": "failed",
                    "report": {"error": "Failed to obtain valid scan ID"}
                })
        
        # Log the URLs and results being passed to the frontend
        print("URLs passed to frontend:", url_results)
        
        return jsonify({"url_analysis": url_results}), 200

    except Exception as e:
        logging.error(f"Error scanning URLs: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/scan-attachments", methods=["POST"])
def scan_attachments_endpoint():
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        attachments = request.json.get("attachments", [])
        if not attachments:
            return jsonify({"error": "No attachments provided"}), 400

        attachment_results = []
        for attachment in attachments:
            logging.info(f"Received attachment data: {attachment.keys()}")  # Debug log
            
            if not attachment.get("content"):
                logging.error(f"No content found for attachment: {attachment.get('name', 'unknown')}")
                continue

            result = {"filename": attachment.get("name", "unknown"), "status": "failed"}
            temp_path = None
            
            try:
                # Extract content safely
                content_data = attachment["content"]
                if isinstance(content_data, str):
                    # Remove data URL prefix if present
                    if 'base64,' in content_data:
                        content_data = content_data.split('base64,')[1]
                    file_content = base64.b64decode(content_data)
                else:
                    logging.error(f"Invalid content format: {type(content_data)}")
                    raise ValueError("Invalid content format")

                # Save file
                temp_path = f"temp_{attachment['name']}"
                with open(temp_path, 'wb') as f:
                    f.write(file_content)
                
                logging.info(f"Successfully saved file: {temp_path}")

                # Process with VirusTotal
                scan_id = scan_file(VIRUSTOTAL_API_KEY, temp_path)
                
                # Validate scan_id
                if scan_id:
                    report = get_file_report(VIRUSTOTAL_API_KEY, scan_id)
                    if report:
                        result.update({
                            "status": "completed",
                            "report": report
                        })
                    else:
                        result["report"] = {"error": "Invalid report data"}
                else:
                    result["report"] = {"error": "Failed to obtain valid scan ID"}

            except KeyError as e:
                logging.error(f"Missing key in attachment data: {e}")
                result["error"] = f"Missing data: {e}"
            except base64.binascii.Error as e:
                logging.error(f"Base64 decoding error: {e}")
                result["error"] = "Invalid file content encoding"
            except Exception as e:
                logging.error(f"Error processing attachment: {str(e)}")
                result["error"] = str(e)
            finally:
                # Cleanup
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
                    logging.info(f"Cleaned up file: {temp_path}")
            
            attachment_results.append(result)

        # Log the attachments and results being passed to the frontend
        print("Attachments passed to frontend:", attachment_results)

        return jsonify({"attachment_analysis": attachment_results}), 200

    except Exception as e:
        logging.error(f"Error in scan-attachments endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500

# API endpoint
@app.route("/scan-email", methods=["POST"])
def scan_email_endpoint():
    try:
        request_id = str(uuid.uuid4())
        logging.info(f"\nProcessing email scan request {request_id}")
        
        # Get both HTML and original content
        html_content = request.json.get("email_text")
        original_content = request.json.get("original_text")
        
        if not html_content or not original_content:
            return jsonify({"error": "Both HTML and original email content are required"}), 400

        metadata = request.json.get("metadata", {})
        
        # Process the email for scanning using HTML content
        result = scan_email(html_content)
        stored_in_db = False
        
        
        if result["label"] == "Phishing Email":
            email_data = {
                'original_email_text': original_content,  # Store original content
                'sender_email': metadata.get('sender', {}).get('email', ''),
                'subject': metadata.get('subject', ''),
                'received_time': metadata.get('received_time', None),
                'confidence': result['confidence'],
                'user_email': metadata.get('user_email', '')
            }
            
            # Add debug logging before storage
            logging.info("Content being stored in database:")
            logging.info(email_data['original_email_text'][:200] + "...")
            
            stored_in_db = store_phishing_email(email_data)
            logging.info(f"Request {request_id}: Storage status: {stored_in_db}")

        return jsonify({
            "request_id": request_id,
            "label": result["label"],
            "confidence": result["confidence"],
            "highlighted_email": result["highlighted_email"],
            "stored_in_db": stored_in_db
        }), 200

    except Exception as e:
        logging.error(f"Error scanning email: {str(e)}")
        return jsonify({"error": str(e)}), 500

def process_virustotal_report(report):
    """Process and simplify VirusTotal report"""
    if not report or 'data' not in report:
        return {"error": "Invalid report data"}
    
    stats = report.get('data', {}).get('attributes', {}).get('stats', {})
    return {
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "undetected": stats.get('undetected', 0),
        "timeout": stats.get('timeout', 0)
    }

def test_db_connection():
    try:
        connection = get_db_connection()
        if connection and connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            logging.info("Database connection test successful")
            return True
    except mysql.connector.Error as err:
        logging.error(f"Database connection test failed: {err}")
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# Add this new endpoint to fetch phishing emails for a specific user
@app.route("/get-phishing-reports/<user_email>", methods=["GET"])
def get_phishing_reports(user_email):
    if not test_db_connection():
        return jsonify({"error": "Database connection test failed"}), 500
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = connection.cursor(dictionary=True)
        
        # Debug logging
        logging.info(f"Fetching reports for user: {user_email}")
        
        query = """
        SELECT 
            id,
            user_email,
            email_content,
            sender_email,
            subject,
            DATE_FORMAT(received_time, '%Y-%m-%d %H:%i:%s') as received_time,
            confidence_score,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
        FROM phishing_emails 
        WHERE user_email = %(user_email)s 
        ORDER BY created_at DESC
        """
        
        # Execute with named parameter
        params = {'user_email': user_email}
        logging.info(f"Executing query with params: {params}")  # Debug log
        
        cursor.execute(query, params)
        phishing_emails = cursor.fetchall()
        
        # Debug logging
        logging.info(f"Found {len(phishing_emails)} reports")
        
        # Process the results
        for email in phishing_emails:
            if email.get('confidence_score') is not None:
                # Convert to float and keep original precision
                email['confidence_score'] = float(email['confidence_score'])
                # Format to 2 decimal places
                email['confidence_score'] = "{:.2f}".format(email['confidence_score'])
        
        return jsonify({
            "status": "success",
            "data": phishing_emails,
            "count": len(phishing_emails)
        }), 200

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error", "message": str(err)}), 500
    except Exception as e:
        logging.error(f"Error fetching phishing reports: {str(e)}")
        return jsonify({"error": "Server error", "message": str(e)}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def register_user(user_email, user_type='guest'):
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Check if user already exists
        check_query = "SELECT user_email, user_type FROM users WHERE user_email = %s"
        cursor.execute(check_query, (user_email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            logging.info(f"User {user_email} already exists with type: {existing_user[1]}")
            return True
            
        # Insert new user with user_type
        insert_query = "INSERT INTO users (user_email, user_type) VALUES (%s, %s)"
        cursor.execute(insert_query, (user_email, user_type))
        connection.commit()
        logging.info(f"New user registered: {user_email} as {user_type}")
        return True
        
    except mysql.connector.Error as err:
        logging.error(f"Failed to register user: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Add OPTIONS handler for the store-user endpoint
@app.route("/store-user", methods=["OPTIONS"])
def handle_options():
    response = jsonify({"status": "ok"})
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response, 200

# Your existing store-user endpoint
@app.route("/store-user", methods=["POST"])
def store_user():
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.json
        user_email = data.get('email')
        user_type = data.get('user_type', 'guest')

        if not user_email:
            return jsonify({"error": "Email is required"}), 400

        success = register_user(user_email, user_type)
        if success:
            return jsonify({"message": "User stored successfully"}), 200
        else:
            return jsonify({"error": "Failed to store user"}), 500

    except Exception as e:
        logging.error(f"Error storing user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/download-phishing-reports/<user_email>", methods=["GET"])
def download_phishing_reports(user_email):
    if not test_db_connection():
        return jsonify({"error": "Database connection test failed"}), 500
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            id,
            user_email,
            email_content,
            sender_email,
            subject,
            DATE_FORMAT(received_time, '%Y-%m-%d %H:%i:%s') as received_time,
            confidence_score,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
        FROM phishing_emails 
        WHERE user_email = %(user_email)s 
        ORDER BY created_at DESC
        """
        
        cursor.execute(query, {'user_email': user_email})
        phishing_emails = cursor.fetchall()
        
        if not phishing_emails:
            return jsonify({"error": "No reports found for this user"}), 404

        # Create CSV content with headers
        csv_content = "ID,User Email,Sender Email,Subject,Received Time,Confidence Score,Created At,Email Content\n"
        
        def clean_csv_field(field):
            """Helper function to clean and escape fields for CSV"""
            if field is None:
                return '""'
            # Convert to string and clean the field
            field_str = str(field)
            # Replace any double quotes with two double quotes (CSV escape sequence)
            field_str = field_str.replace('"', '""')
            # Replace any newlines or carriage returns with spaces
            field_str = field_str.replace('\n', ' ').replace('\r', ' ')
            # Wrap in quotes to handle commas and other special characters
            return f'"{field_str}"'
        
        # Add each row to the CSV
        for email in phishing_emails:
            row = [
                clean_csv_field(email['id']),
                clean_csv_field(email['user_email']),
                clean_csv_field(email['sender_email']),
                clean_csv_field(email['subject']),
                clean_csv_field(email['received_time']),
                clean_csv_field(email['confidence_score']),
                clean_csv_field(email['created_at']),
                clean_csv_field(email['email_content'])
            ]
            csv_content += ','.join(row) + '\n'

        # Create response with CSV file
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'phishing_reports_{user_email}_{timestamp}.csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Add debug logging
        logging.info(f"Generated CSV report for user {user_email} with {len(phishing_emails)} entries")
        
        return response

    except Exception as e:
        logging.error(f"Error downloading phishing reports: {str(e)}")
        return jsonify({"error": "Server error", "message": str(e)}), 500
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == "__main__":
    # Test database connection on startup
    if not test_db_connection():
        logging.error("Failed to connect to database. Please check your configuration.")
        sys.exit(1)
    
    # Run the Flask app
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        # Add these options for better CORS handling
        threaded=True,
        use_reloader=True
    )
