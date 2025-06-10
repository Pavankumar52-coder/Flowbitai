# Import necessary libraries
import json
import re # Regular Expressions
import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException # API
from enum import Enum
import fitz  # PyMuPDF
import redis # Redis Server
from faker import Faker

# FastAPI App
app = FastAPI()
fake = Faker() # Faker for webhook data
# Connection to redis for memory allocation
r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

# Class for file formats
class FileFormat(str, Enum):
    email = "email"
    json = "json"
    pdf = "pdf"

# Class for identifying intent(pdf or json or email)
class Intent(str, Enum):
    rfq = "RFQ"
    complaint = "Complaint"
    invoice = "Invoice"
    regulation = "Regulation"
    fraud_risk = "Fraud Risk"
    unknown = "Unknown" # Added for better handling of uncategorized intent

# Function for Shared Memory Store
def write_to_memory(key: str, value: dict):
    timestamp = datetime.datetime.now().isoformat()
    # Store with a unique ID for each entry, not just filename, to allow multiple entries for the same file
    unique_key = f"{key}:{timestamp}"
    r.set(unique_key, json.dumps(value))
    print(f"Memory: Wrote data to key: {unique_key}")

# Function to read memory
def read_memory():
    memory_content = {}
    for key in r.scan_iter(): # Use scan_iter for potentially large datasets
        try:
            memory_content[key] = json.loads(r.get(key))
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON for key {key}. Skipping.")
    return memory_content

# 1. CLassifier Agent
def classify_file(content: str, filename: str):
    metadata = {
        'format': None,
        'intent': Intent.unknown # Default to unknown intent
    }
    if filename.lower().endswith(".pdf"):
        metadata['format'] = FileFormat.pdf
        lowered = content.lower()
        if "invoice" in lowered or re.search(r'total|amount due|bill', lowered):
            metadata['intent'] = Intent.invoice
        elif re.search(r'gdpr|fda|hipaa|compliance|regulation', lowered):
            metadata['intent'] = Intent.regulation
        elif re.search(r'fraud|suspicious|alert', lowered): # Simple keyword for fraud risk
            metadata['intent'] = Intent.fraud_risk
        elif re.search(r'request for quote|quotation|bid', lowered):
            metadata['intent'] = Intent.rfq
        # If no specific intent found, it remains Intent.unknown

    elif filename.lower().endswith(".json"):
        metadata['format'] = FileFormat.json
        lowered = content.lower()
        if "fraud" in lowered or "alert" in lowered or "suspicious" in lowered:
            metadata['intent'] = Intent.fraud_risk
        elif re.search(r'quote|price|request', lowered):
            metadata['intent'] = Intent.rfq
        # If no specific intent found, it remains Intent.unknown

    elif filename.lower().endswith(".eml") or (metadata['format'] is None and "@" in content and "subject:" in content.lower()):
        # Basic check for email-like content if no specific file extension
        metadata['format'] = FileFormat.email
        lowered = content.lower()
        if "complaint" in lowered or "dissatisfaction" in lowered or "unacceptable" in lowered or "angry" in lowered:
            metadata['intent'] = Intent.complaint
        elif re.search(r'request for quote|quotation|bid', lowered):
            metadata['intent'] = Intent.rfq
        # If no specific intent found, it remains Intent.unknown
    else:
        # If file type is not determined by it's extension, assumes it's an email/json/pdf if it contains common email headers/json format/pdf extension
        if "from:" in content.lower() and "subject:" in content.lower():
            metadata['format'] = FileFormat.email
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format or content type.")

    print(f"Classifier: Format - {metadata['format']}, Intent - {metadata['intent']}")
    return metadata

# 2.Email Agent
def process_email(content: str):
    """Extracts sender, urgency, tone, and suggests an action from email content."""
    sender_match = re.search(r"From:\s*(.*)", content, re.IGNORECASE)
    sender = sender_match.group(1).strip() if sender_match else "unknown"

    # Improved urgency detection
    urgency_keywords = r"urgent|asap|immediate|critical|now"
    urgency = "high" if re.search(urgency_keywords, content, re.IGNORECASE) else "low"
    if re.search(r"escalate|please respond soon", content, re.IGNORECASE) and urgency == "low":
        urgency = "medium"

    # Improved tone detection
    tone_angry_keywords = r"angry|not happy|dissatisfied|unacceptable|complaint|frustrated|upset"
    tone_threatening_keywords = r"legal action|lawsuit|demand|consequences"
    tone = "polite" # Default tone
    if re.search(tone_threatening_keywords, content, re.IGNORECASE):
        tone = "threatening"
    elif re.search(tone_angry_keywords, content, re.IGNORECASE):
        tone = "angry"

    # Action based on tone and urgency
    action = "log and close"
    if tone in ["angry", "threatening"] or urgency == "high":
        action = "escalate to CRM"
    elif urgency == "medium":
        action = "review and prioritize"

    result = {
        "sender": sender,
        "urgency": urgency,
        "tone": tone,
        "suggested_action": action, # Renamed for clarity
        "issue_request": content # Storing full content or specific extraction later
    }
    print(f"Email Agent: Processed. Sender: {result['sender']}, Urgency: {result['urgency']}, Tone: {result['tone']}")
    return result

# 3.JSON Agent
def process_json(content: str):
    """Parses JSON content, validates against required fields, and flags anomalies."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"JSON Agent: Invalid JSON - {str(e)}")
        return {
            "valid": False,
            "anomalies": [f"Invalid JSON format: {str(e)}"],
            "parsed_data": None
        }
    required_fields = ["id", "timestamp", "type", "payload"]
    anomalies = []

    for field in required_fields:
        if field not in data:
            anomalies.append(f"Missing required field: '{field}'")
    if 'id' in data and not isinstance(data['id'], (str, int)):
        anomalies.append(f"Field 'id' has incorrect type: {type(data['id'])}")
    if 'timestamp' in data and not isinstance(data['timestamp'], str):
        anomalies.append(f"Field 'timestamp' has incorrect type: {type(data['timestamp'])}")
    is_valid = len(anomalies) == 0
    action_needed = "log alert" if not is_valid else "process data"
    result = {
        "valid": is_valid,
        "anomalies": anomalies,
        "parsed_data": data,
        "suggested_action": action_needed
    }
    print(f"JSON Agent: Validation - {result['valid']}, Anomalies: {result['anomalies']}")
    return result

# Processing PDF with PyMuPDF(FITZ)
def process_pdf(content: bytes, intent: Intent):
    extracted_text = ""
    try:
        doc = fitz.open(stream=content, filetype="pdf")
        extracted_text = "\n".join(page.get_text() for page in doc)
        print("PDF Agent: Successfully extracted text from PDF.")
    except Exception as e:
        print(f"PDF Agent: Error opening or extracting text from PDF: {e}")
        return {
            "success": False,
            "error": f"Failed to process PDF: {str(e)}",
            "extracted_data": {},
            "flags": []
        }
    result = {
        "success": True,
        "extracted_text_snippet": extracted_text[:500] + "..." if len(extracted_text) > 500 else extracted_text,
        "extracted_data": {}, # Structured data will go here (invoice, policy)
        "flags": [],
        "suggested_action": "review document" # Default action
    }
    lowered_text = extracted_text.lower()
    # Invoice processing
    if intent == Intent.invoice or "invoice" in lowered_text or "total amount" in lowered_text:
        result["type"] = "invoice"
        invoice_total_match = re.search(r'(?:total|amount due|balance due):\s*\$?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)', lowered_text)
        if invoice_total_match:
            total_str = invoice_total_match.group(1).replace(',', '')
            try:
                total_val = float(total_str)
                result["extracted_data"]["invoice_total"] = total_val
                if total_val > 10000:
                    result["flags"].append("Invoice total exceeds 10,000")
                    result["suggested_action"] = "require approval"
            except ValueError:
                result["extracted_data"]["invoice_total_parse_error"] = total_str
        else:
            result["flags"].append("Invoice total not found or unparseable")

        # Basic line item parsing (can be expanded with regex for specific formats)
        line_item_matches = re.findall(r'(\d+)\s+([\w\s]+?)\s+\$?(\d+(?:\.\d{2})?)\s+\$?(\d+(?:\.\d{2})?)', extracted_text)
        if line_item_matches:
            result["extracted_data"]["line_items"] = []
            for qty, desc, unit_price, total_price in line_item_matches:
                result["extracted_data"]["line_items"].append({
                    "quantity": int(qty),
                    "description": desc.strip(),
                    "unit_price": float(unit_price),
                    "total_price": float(total_price)
                })

    # Policy/Regulation/Fraud Risk processing
    if intent in [Intent.regulation, Intent.fraud_risk] or re.search(r'gdpr|fda|hipaa|compliance|risk|fraud', lowered_text):
        result["type"] = "policy/compliance"
        keywords_found = []
        if "gdpr" in lowered_text:
            keywords_found.append("GDPR")
            result["flags"].append("Compliance risk: GDPR mentioned")
        if "fda" in lowered_text:
            keywords_found.append("FDA")
            result["flags"].append("Compliance risk: FDA mentioned")
        if "hipaa" in lowered_text:
            keywords_found.append("HIPAA")
            result["flags"].append("Compliance risk: HIPAA mentioned")
        if "fraud" in lowered_text or "suspicious" in lowered_text:
            keywords_found.append("Fraud/Suspicious Activity")
            result["flags"].append("Potential Fraud Risk")
            result["suggested_action"] = "investigate fraud"

        result["extracted_data"]["compliance_keywords"] = keywords_found
        if keywords_found:
            result["suggested_action"] = "compliance review"

    print(f"PDF Agent: Processed. Flags: {result['flags']}, Suggested Action: {result['suggested_action']}")
    return result

# Action Router with chained actions and simulation
def route_action(agent_result: dict, intent: Intent, file_format: FileFormat):
    actions_to_trigger = []
    # Email-specific actions
    if file_format == FileFormat.email:
        if agent_result.get('suggested_action') == "escalate to CRM":
            actions_to_trigger.append({"POST": "/crm/escalate", "payload": {"sender": agent_result.get('sender'), "issue": agent_result.get('issue_request')}})
        elif agent_result.get('suggested_action') == "review and prioritize":
            actions_to_trigger.append({"POST": "/ticket/create", "payload": {"description": "Email requires review", "priority": "medium"}})
        elif agent_result.get('suggested_action') == "log and close":
            actions_to_trigger.append({"POST": "/log/email_processed"})
    # JSON-specific actions
    elif file_format == FileFormat.json:
        if not agent_result.get('valid', True): # If JSON is not valid
            actions_to_trigger.append({"POST": "/risk_alert/json_anomaly", "payload": {"anomalies": agent_result.get('anomalies'), "data_snippet": agent_result.get('parsed_data')}})
        else:
            actions_to_trigger.append({"POST": "/data_ingestion/webhook_process", "payload": {"data": agent_result.get('parsed_data')}})
    # PDF-specific actions
    elif file_format == FileFormat.pdf:
        if "Invoice total exceeds 10,000" in agent_result.get('flags', []):
            actions_to_trigger.append({"POST": "/invoice/approval_request", "payload": {"invoice_data": agent_result.get('extracted_data')}})
        if "Compliance risk: GDPR mentioned" in agent_result.get('flags', []) or \
           "Compliance risk: FDA mentioned" in agent_result.get('flags', []) or \
           "Compliance risk: HIPAA mentioned" in agent_result.get('flags', []):
            actions_to_trigger.append({"POST": "/compliance/review", "payload": {"document_type": agent_result.get('type'), "keywords": agent_result.get('extracted_data', {}).get('compliance_keywords')}})
        if "Potential Fraud Risk" in agent_result.get('flags', []):
             actions_to_trigger.append({"POST": "/risk_alert/fraud_investigation", "payload": {"document_info": agent_result.get('extracted_text_snippet')}})

    # Default action if no specific action was triggered above
    if not actions_to_trigger:
        actions_to_trigger.append({"POST": "/log/default_processing_completed"})

    # Simulate REST calls (for now just print)
    for action in actions_to_trigger:
        method = list(action.keys())[0]
        endpoint = action[method]
        payload = action.get('payload', {})
        print(f"Simulated {method} call to {endpoint} with payload: {payload}")

    return actions_to_trigger

# --- Main Upload Endpoint ---
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    filename = file.filename
    # Determine content_str for text-based classification/processing
    content_str = ""
    if filename.lower().endswith(('.json', '.eml')):
        content_str = content.decode('utf-8', errors='ignore')
    elif filename.lower().endswith('.pdf'):
        try:
            doc = fitz.open(stream=content, filetype="pdf")
            content_str = "\n".join(page.get_text() for page in doc)[:1000] # Snippet for classifier
        except Exception:
            content_str = "" # If PDF extraction fails here, classifier still gets filename
    try:
        classification = classify_file(content_str, filename)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Classifier Agent failed: {str(e)}")

    agent_result = {}

    try:
        if classification['format'] == FileFormat.email:
            agent_result = process_email(content_str)
        elif classification['format'] == FileFormat.json:
            agent_result = process_json(content_str)
        elif classification['format'] == FileFormat.pdf:
            # Pass original binary content to PDF agent
            agent_result = process_pdf(content, classification['intent'])
    except Exception as e:
        print(f"Error in {classification['format']} agent: {e}")
        # Log the error in agent_result or decision_trace
        agent_result = {"error": f"Processing failed: {str(e)}", "success": False}

    actions_triggered = route_action(agent_result, classification['intent'], classification['format'])

    # 4. Storing Decision Trace in Shared Memory
    memory_entry = {
        "source": filename,
        "timestamp": datetime.datetime.now().isoformat(),
        "classification": classification,
        "agent_result": agent_result,
        "action_triggered": actions_triggered,
        "decision_trace": {
            "classifier": classification,
            f"{classification['format']}_agent_output": agent_result,
            "routed_actions": actions_triggered
        }
    }
    write_to_memory(filename, memory_entry)
    return memory_entry

# View Memory Endpoint
@app.get("/memory")
def view_memory():
    return read_memory()