import os
from PyPDF2 import PdfReader
import docx
from bs4 import BeautifulSoup
from app.models import db, FileContent

def load_pdf(file_path):
    reader = PdfReader(file_path)
    text = ''
    for page in reader.pages:
        text += page.extract_text()
    return text

def load_docx(file_path):
    doc = docx.Document(file_path)
    text = ''
    for paragraph in doc.paragraphs:
        text += paragraph.text
    return text

def load_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        soup = BeautifulSoup(file, 'html.parser')
        return soup.get_text()

def load_files_from_directory(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        # Verificar se o arquivo já foi carregado
        existing_file = FileContent.query.filter_by(filename=filename).first()
        if existing_file:
            print(f"{filename} already exists in the database. Skipping.")
            continue

        if filename.endswith('.pdf'):
            content = load_pdf(file_path)
        elif filename.endswith('.docx'):
            content = load_docx(file_path)
        elif filename.endswith('.html'):
            content = load_html(file_path)
        else:
            continue

        file_content = FileContent(filename=filename, content=content)
        db.session.add(file_content)
    db.session.commit()
