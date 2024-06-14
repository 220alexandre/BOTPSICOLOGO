import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from senha import SECRET_KEY, SQLALCHEMY_DATABASE_URI, API_KEY, STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY
import stripe

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('chat'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        plan = request.form.get('plan')
        current_user.plan = plan
        db.session.commit()
        flash('Plan updated successfully.')
    return render_template('profile.html')

@app.route('/chat', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')
        print(f"Recebido do usuário: {user_message}")

        # Verificação do plano do usuário
        plan_limits = {'free': 300, 'standard': 5000, 'premium': 10000}
        if current_user.token_usage >= plan_limits[current_user.plan]:
            return jsonify({"error": "Token limit exceeded for your plan."})

        # Corpo da mensagem
        body_msg = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_message}
            ]
        }

        # Enviando a requisição para a API da OpenAI
        req = requests.post(link, headers=headers, data=json.dumps(body_msg))
        print(f"Requisição enviada para OpenAI")

        # Verificando a resposta
        if req.status_code == 200:
            response = req.json()
            response_message = response['choices'][0]['message']['content']
            print(f"Resposta da OpenAI: {response_message}")

            # Atualizando o uso de tokens do usuário
            token_count = sum(len(message['content']) for message in body_msg['messages'])
            current_user.token_usage += token_count
            db.session.commit()

            return jsonify({"response": response_message})
        else:
            print(f"Erro na requisição: {req.status_code}")
            print(req.text)
            return jsonify({"error": "Erro na requisição"}), req.status_code
    return render_template('chat.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
