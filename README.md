# BOTPSICOLOGO

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-Backend-black)
![MySQL](https://img.shields.io/badge/Database-MySQL-orange)
![Redis](https://img.shields.io/badge/Redis-Rate%20Limiting-red)
![Stripe](https://img.shields.io/badge/Stripe-Payments-purple)
![License](https://img.shields.io/badge/License-MIT-green)

Backend-focused web application built with Flask to manage companies, employees, token usage, file ingestion, and secure authentication.

This project was developed as a portfolio demonstration of backend architecture, security best practices, and scalable system design.

---

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Features](#features)
- [Security](#security)
- [Installation](#installation)
- [File Processing](#file-processing)
- [Project Structure](#project-structure)
- [Future Improvements](#future-improvements)
- [Author](#author)

---

## Overview

BOTPSICOLOGO is a modular backend system designed to manage companies and employees with token usage tracking, scheduled resets, payment integration, and file content processing.

The system follows clean architecture principles using Flask’s Application Factory Pattern and modular Blueprints.

---

## Tech Stack

- Python 3.10+
- Flask (Application Factory Pattern)
- Flask-SQLAlchemy
- Flask-Migrate (Alembic)
- MySQL
- Redis (Rate Limiting)
- Flask-Login
- Flask-WTF (CSRF Protection)
- APScheduler
- Stripe API
- PyPDF2
- python-docx
- BeautifulSoup

---

## Architecture

The project uses a modular structure based on Blueprints and extensions.

### Key Architectural Decisions

- Application Factory Pattern
- Separation of concerns (routes, models, utils)
- Database versioning via Alembic
- Role-based access control (Admin / User)
- Scheduled background tasks
- Redis-backed rate limiting
- Secure HTTP response headers

### System Flow

User  
↓  
Flask Application  
↓  
Blueprints (Admin / Auth / Main / Stripe)  
↓  
Database (MySQL)  
↘ Redis (Rate Limiting)  
↘ APScheduler (Monthly Token Reset)  
↘ Stripe API  

---

## Features

- User authentication and session management
- Admin dashboard
- Company creation and management
- Employee management
- Token usage tracking
- Monthly automated token reset
- Stripe payment integration
- File content extraction and storage (PDF, DOCX, HTML)
- CSRF protection
- Rate limiting per IP
- Secure HTTP headers configuration

---

## Security

- CSRF protection enabled globally
- Role-based route protection
- Rate limiting using Redis
- Secure HTTP headers:
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
- Controlled database migrations

---

## Installation

📌 1. Clone the repository
```bash
git clone https://github.com/220alexandre/BOTPSICOLOGO.git
cd BOTPSICOLOGO
```
📌 2. Create and activate virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```
📌 3. Install project dependencies
```bash
pip install -r requirements.txt
```
📌 4. Create .env file

Create a .env file in the project root with the following:
```bash
SECRET_KEY=your_secret_key_here
DATABASE_URL=mysql+pymysql://root:your_password@localhost/botpsicologo
API_KEY=your_openai_api_key_here

STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
STRIPE_WEBHOOK_SECRET=your_webhook_secret

REDIS_URL=redis://localhost:6379/0
```
💡 Do not push the .env file to GitHub — sensitive keys must stay local.

📌 5. Create the MySQL database

In your MySQL server (e.g., phpMyAdmin or terminal):
```bash
CREATE DATABASE botpsicologo;
```
Make sure the DATABASE_URL in your .env matches the database name.

📌 6. Run Migrations
```bash
flask db migrate -m "Initial migration"
flask db upgrade
```
This creates all tables based on your models.

📌 7. Ensure Redis is running

Default configuration:
```bash
redis://localhost:6379/0
```
Redis is required for rate limiting and certain scheduler features.

📌 8. Run the application
```bash
flask run
```
The backend will start locally.
You can now access admin and API routes as documented.

📂 File Processing

To load documents from the files directory into the database:
```bash
python -m app.utils.file_loader
```
Supported formats:

- PDF

- DOCX

- HTML

Extracted text is stored in the database.

### Project Structure
```bash
app/
│
├── routes/
│   ├── admin_routes.py
│   ├── auth_routes.py
│   ├── main_routes.py
│   └── stripe_routes.py
│
├── models.py
├── extensions.py
├── utils/
│   └── file_loader.py
│
migrations/
config.py
run.py
```

### Future Improvements

Docker containerization

Unit and integration tests with pytest

CI/CD pipeline (GitHub Actions)

API documentation (Swagger / OpenAPI)

Cloud deployment (AWS / GCP)

Background job queue (Celery)

### Author

Lucas Alexandre Sampaio Ferreira 
Backend Developer focused on scalable and secure systems.