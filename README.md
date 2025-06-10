# Flowbitai

This project is an AI-powered risk detection system for processing multimodal inputs. It classifies and analyzes PDF, email, and JSON documents to identify fraud or compliance risks and routes them to the appropriate backend services.

# Architecture Explanation:
1. User uploads the data in pdf/email/json formats.
2. The first agent classifier intent agent classifies the format and intent present in given files.
3. Email agent extracts the text from emails.
4. Pdf agent extracts the required text from pdf files.
5. JSON agent extracts text from json files.
6. Based on the intent and flags the action route dynamically chains a follow-up actions.
7. Triggers POST to appropriate endpoints.
8. Finally /memory endpoint stores the results in memory.

# Agents Logic:
ClassifierAgent: Uses file extension/content to detect format and risk intent.
PDFAgent: Parses the text present in the pdf.
JSONAgent: Validates fraud-alert schema through text present in json format.
EmailAgent: Extracts metadata & threat intent through emails.

# AI Agent Running:
1. run 'docker-compose build --no-cache' in terminal.
2. run 'docker-compose up'.
3. open the api link(https://localhost:8000/docs) present in terminal.
