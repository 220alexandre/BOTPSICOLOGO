import os
import logging
from PyPDF2 import PdfReader
import docx
from bs4 import BeautifulSoup

from app import create_app
from app.extensions import db
from app.models import FileContent

logging.basicConfig(level=logging.INFO)

def load_pdf(file_path):
    try:
        reader = PdfReader(file_path)
        text = ''.join(page.extract_text() for page in reader.pages)
        return text
    except Exception as e:
        logging.error(f"Error loading PDF {file_path}: {e}")
        return ''

def load_docx(file_path):
    try:
        doc = docx.Document(file_path)
        text = '\n'.join(paragraph.text for paragraph in doc.paragraphs)
        return text
    except Exception as e:
        logging.error(f"Error loading DOCX {file_path}: {e}")
        return ''

def load_html(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            soup = BeautifulSoup(file, 'html.parser')
            return soup.get_text()
    except Exception as e:
        logging.error(f"Error loading HTML {file_path}: {e}")
        return ''

def load_files_from_directory(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        existing_file = FileContent.query.filter_by(filename=filename).first()
        if existing_file:
            logging.info(f"{filename} already exists in the database. Skipping.")
            continue

        content = ''
        if filename.endswith('.pdf'):
            content = load_pdf(file_path)
        elif filename.endswith('.docx'):
            content = load_docx(file_path)
        elif filename.endswith('.html'):
            content = load_html(file_path)

        if content:
            file_content = FileContent(filename=filename, content=content)
            db.session.add(file_content)
            logging.info(f"{filename} loaded and added to the database.")

    db.session.commit()



from app.models import FileContent
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        load_files_from_directory('files')
        print("All files processed.")
