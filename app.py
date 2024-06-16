import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from senha import SECRET_KEY, SQLALCHEMY_DATABASE_URI, API_KEY, STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET
import stripe
import requests
import json
from PyPDF2 import PdfReader
import docx
from bs4 import BeautifulSoup
from redis import Redis
from sqlalchemy.dialects.mysql import LONGTEXT


app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuração do Redis
redis_host = "localhost"  # Substitua pelo host do seu servidor Redis
redis_port = 6379         # Substitua pela porta do seu servidor Redis
redis_password = None     # Substitua pela senha do seu servidor Redis, se aplicável

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f"redis://{redis_host}:{redis_port}/0"
)

stripe.api_key = STRIPE_SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    plan = db.Column(db.String(50), nullable=False, default='free')
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    company = db.relationship('Company', back_populates='users')
    employee = db.relationship('Employee', uselist=False, back_populates='user')  # Adicionado

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    user_limit = db.Column(db.Integer, nullable=False)
    token_limit = db.Column(db.Integer, nullable=False)
    current_token_usage = db.Column(db.Integer, nullable=False, default=0)

    users = db.relationship('User', back_populates='company')
    employees = db.relationship('Employee', back_populates='company')
    custom_plans = db.relationship('CustomPlan', order_by='CustomPlan.id', back_populates='company')

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Adicionado
    token_usage = db.Column(db.Integer, nullable=False, default=0)
    user_limit = db.Column(db.Integer, nullable=False, default=0)
    name = db.Column(db.String(100), nullable=False)

    company = db.relationship('Company', back_populates='employees')
    user = db.relationship('User', back_populates='employee')  # Adicionado


class FileContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    content = db.Column(LONGTEXT, nullable=False)

class CustomPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    tokens_per_user = db.Column(db.Integer, nullable=False)

    company = db.relationship('Company', back_populates='custom_plans')
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

with app.app_context():
    db.create_all()
    load_files_from_directory('files')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('chat'))
        else:
            flash('Login failed. Check your email and password.')
    return render_template('login.html')

@app.route('/plans')
@login_required
def plans():
    return render_template('plans.html')
#admin dashboard
# Adicione a rota para o painel de administração
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('home'))
    companies = Company.query.all()
    users = User.query.all()
    employers = Employee.query.all()
    return render_template('admin_dashboard.html', 
                            companies=companies,
                            users=users,
                            employees=employers)

@app.route('/admin/cancel_subscription/<user_id>', methods=['POST'])
@login_required
def admin_cancel_subscription(user_id):
    if not current_user.is_admin:
        flash('Acesso negado.')
        return redirect(url_for('home'))

    user = User.query.get(user_id)
    if user and user.stripe_subscription_id:
        try:
            stripe.Subscription.delete(user.stripe_subscription_id)
            user.stripe_subscription_id = None
            user.plan = 'free'
            db.session.commit()
            flash('Assinatura cancelada com sucesso.')
        except stripe.error.StripeError as e:
            flash(f'Ocorreu um erro ao cancelar a assinatura: {str(e)}')
    return redirect(url_for('admin_panel'))

@app.route('/create_company', methods=['GET', 'POST'])
@login_required
def create_company():
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        user_limit = request.form.get('user_limit')
        token_limit = request.form.get('token_limit')
        monthly_cost = request.form.get('monthly_cost')
        
        new_company = Company(name=name, user_limit=user_limit, token_limit=token_limit, monthly_cost=monthly_cost)
        db.session.add(new_company)
        db.session.commit()
        
        flash('Empresa criada com sucesso.')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_company.html')

@app.route('/manage_company/<int:company_id>', methods=['GET', 'POST'])
@login_required
def manage_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('home'))
    
    company = Company.query.get_or_404(company_id)
    return render_template('manage_company.html', company=company)
@app.route('/remove_employee/<int:employee_id>', methods=['POST'])
@login_required
def remove_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    if not current_user.is_admin or current_user.company_id != employee.company_id:
        flash("Você não tem permissão para remover este empregado.")
        return redirect(url_for('profile'))

    db.session.delete(employee)
    db.session.commit()
    flash("Empregado removido com sucesso.")
    return redirect(url_for('profile'))


@app.route('/company/<int:company_id>/employees', methods=['GET', 'POST'])
@login_required
def manage_employees(company_id):
    company = Company.query.get_or_404(company_id)

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        existing_employee = Employee.query.filter_by(email=email).first()
        if existing_employee:
            flash('Funcionário com este email já existe.')
        else:
            new_employee = Employee(name=name, email=email, company_id=company.id)
            db.session.add(new_employee)
            db.session.commit()
            flash('Funcionário adicionado com sucesso.')

    employees = Employee.query.filter_by(company_id=company_id).all()
    return render_template('manage_employees.html', company=company, employees=employees)

@app.route('/create-custom-plan', methods=['GET', 'POST'])
@login_required
def create_custom_plan():
    if not current_user.is_admin:
        flash('Apenas administradores podem criar planos personalizados.')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        company_id = request.form.get('company_id', type=int)
        price = request.form.get('price', type=float)
        tokens_per_user = request.form.get('tokens_per_user', type=int)

        plan = CustomPlan(company_id=company_id, price=price, tokens_per_user=tokens_per_user)
        db.session.add(plan)
        db.session.commit()
        flash('Plano personalizado criado com sucesso.')
        return redirect(url_for('admin_dashboard'))

    companies = Company.query.all()
    
    return render_template('create_custom_plan.html', companies=companies)


@app.route('/update_company/<int:company_id>', methods=['POST'])
@login_required
def update_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('home'))
    
    company = Company.query.get_or_404(company_id)
    company.plan = request.form.get('plan')
    company.token_limit = request.form.get('token_limit')
    company.monthly_cost = request.form.get('monthly_cost')
    db.session.commit()
    
    flash('Empresa atualizada com sucesso.')
    return redirect(url_for('manage_company', company_id=company_id))

@app.route('/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('home'))
    
    company = Company.query.get_or_404(company_id)
    db.session.delete(company)
    db.session.commit()
    
    flash('Empresa deletada com sucesso.')
    return redirect(url_for('admin_dashboard'))
#fim admin
@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    plan_id = request.form.get('plan_id')
    
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card', 'pix'],
            line_items=[{
                'price': plan_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('profile', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('profile', _external=True),
            customer_email=current_user.email
        )
        return jsonify({'id': session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        user = User(email=email, name=name, registration_date=datetime.utcnow())
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('chat'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    plan_names = {
        'free': 'Grátis',
        'standard': 'Padrão Mensal',
        'premium': 'Premium Mensal',
        'standard_annual': 'Padrão Anual',
        'premium_annual': 'Premium Anual'
    }
    plan_limits = {
        'free': 300,
        'standard': 5000,
        'premium': 10000,
        'standard_annual': 5000,
        'premium_annual': 10000
    }
    company_name = current_user.company.name if current_user.company else 'Nenhuma'
    company_token_usage = current_user.company.current_token_usage if current_user.company else 'N/A'
    company_token = current_user.company.token_limit if current_user.company else 'N/A'
    
    if request.method == 'POST':
        plan = request.form.get('plan')
        current_user.plan = plan
        db.session.commit()
        flash('Plano atualizado com sucesso.')
    
    return render_template('profile.html', 
                           plan_name=plan_names.get(current_user.plan, 'Grátis'), 
                           plan_limits=plan_limits,
                           company_name=company_name,
                           company_token_usage=company_token_usage,
                           company_token=company_token)

@app.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    if current_user.stripe_subscription_id:
        try:
            stripe.Subscription.delete(current_user.stripe_subscription_id)
            current_user.stripe_subscription_id = None
            current_user.plan = 'free'
            db.session.commit()
            flash('Assinatura cancelada com sucesso.')
        except stripe.error.StripeError as e:
            flash(f'Ocorreu um erro ao cancelar a assinatura: {str(e)}')
    return redirect(url_for('profile'))

@app.route('/checkout')
@login_required
def checkout():
    return render_template('checkout.html', key=STRIPE_PUBLISHABLE_KEY)

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    plan_id = request.form.get('plan_id')
    token = request.form.get('stripeToken')

    try:
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                source=token
            )
            current_user.stripe_customer_id = customer.id
        else:
            customer = stripe.Customer.retrieve(current_user.stripe_customer_id)

        subscription = stripe.Subscription.create(
            customer=customer.id,
            items=[{'plan': plan_id}],
        )

        current_user.stripe_subscription_id = subscription.id
        current_user.plan = plan_id
        db.session.commit()

        flash('Subscription was successful.')
        return redirect(url_for('profile'))

    except stripe.error.StripeError as e:
        flash(f'Something went wrong with the subscription: {str(e)}')
        return redirect(url_for('checkout'))

headers = {
    "Authorization": f"Bearer " + API_KEY,
    "Content-Type": "application/json"
}
link = 'https://api.openai.com/v1/chat/completions'


@app.route('/chat', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')

        # Verificação do plano do usuário ou da empresa
        if current_user.company_id:
            company = Company.query.get(current_user.company_id)
            plan_limits = company.token_limit
            token_usage = company.current_token_usage
        else:
            plan_limits = {'free': 300, 'standard': 5000, 'premium': 10000, 'standard_annual': 5000, 'premium_annual': 10000}
            token_usage = current_user.token_usage

        if token_usage >= plan_limits:
            return jsonify({"error": "Token limit exceeded for your plan."})

        # Corpo da mensagem
        body_msg = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "user", "content": user_message}
            ]
        }

        # Enviando a requisição para a API da OpenAI
        req = requests.post(link, headers=headers, data=json.dumps(body_msg))

        # Verificando a resposta
        if req.status_code == 200:
            response = req.json()
            response_message = response['choices'][0]['message']['content']

            # Atualizando o uso de tokens do usuário ou da empresa
            token_count = sum(len(message['content']) for message in body_msg['messages'])
            if current_user.company_id:
                company.current_token_usage += token_count
                db.session.commit()
            else:
                current_user.token_usage += token_count
                db.session.commit()

            return jsonify({"response": response_message})
        else:
            return jsonify({"error": "Erro na requisição"}), req.status_code
    return render_template('chat.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = STRIPE_WEBHOOK_SECRET

    event = None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify(success=False), 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Fulfill the purchase...
        customer_email = session.get('customer_email')
        subscription_id = session.get('subscription')
        
        user = User.query.filter_by(email=customer_email).first()
        if user:
            user.stripe_subscription_id = subscription_id
            user.plan = session['display_items'][0]['plan']['id']
            db.session.commit()

    return jsonify(success=True)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://js.stripe.com; style-src 'self' 'unsafe-inline'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
