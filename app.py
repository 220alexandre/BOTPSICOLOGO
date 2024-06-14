import os
import stripe
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from senha import SECRET_KEY, SQLALCHEMY_DATABASE_URI, API_KEY, STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET

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
    return render_template('plans.html', key=STRIPE_PUBLISHABLE_KEY)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.get_json()
    plan_id = data.get('plan_id')
    
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
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
    plan_names = {
        'free': 'Grátis',
        'standard': 'Padrão Mensal',
        'premium': 'Premium Mensal',
        'standard_annual': 'Padrão Anual',
        'premium_annual': 'Premium Anual'
    }
    return render_template('profile.html', plan_name=plan_names.get(current_user.plan, 'Grátis'))

@app.route('/cancel_subscription', methods=['POST'])
@login_required
def cancel_subscription():
    try:
        if current_user.stripe_subscription_id:
            stripe.Subscription.delete(current_user.stripe_subscription_id)
            current_user.plan = 'free'
            current_user.stripe_subscription_id = None
            db.session.commit()
            flash('Assinatura cancelada com sucesso.')
        else:
            flash('Você não tem uma assinatura ativa para cancelar.')
    except Exception as e:
        flash(f'Erro ao cancelar a assinatura: {str(e)}')
    return redirect(url_for('profile'))

@app.route('/chat', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')
        print(f"Recebido do usuário: {user_message}")

        # Verificação do plano do usuário
        plan_limits = {'free': 300, 'standard': 5000, 'premium': 10000, 'standard_annual': 5000, 'premium_annual': 10000}
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

@app.route('/webhook', methods=['POST'])
@csrf.exempt  # Desabilitar CSRF para esta rota
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = STRIPE_WEBHOOK_SECRET

    print("Recebendo webhook...")
    print(f"Payload: {payload}")
    print(f"Signature Header: {sig_header}")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        print(f"Evento construído: {event}")
    except ValueError as e:
        # Invalid payload
        print("Payload inválido", e)
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print("Assinatura inválida", e)
        return jsonify(success=False), 400
    except Exception as e:
        # General exception handler for any other errors
        print("Erro geral ao processar o webhook", e)
        return jsonify(success=False), 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        print("Evento checkout.session.completed recebido")
        session = event['data']['object']
        customer_email = session['customer_details']['email']
        subscription_id = session['subscription']
        
        # Find the user by email
        user = User.query.filter_by(email=customer_email).first()
        if user:
            print(f"Usuário encontrado: {user.email}")
            user.stripe_subscription_id = subscription_id

            # Atualize o plano do usuário com base no subscription ID
            subscription = stripe.Subscription.retrieve(subscription_id)
            price_id = subscription['items']['data'][0]['price']['id']
            print(f"ID do preço: {price_id}")

            if price_id == 'price_1PRMV8P27E94kbegb9WLZxk9':
                user.plan = 'premium'
            elif price_id == 'price_1PRMVQP27E94kbegI68UwEpB':
                user.plan = 'standard'
            elif price_id == 'price_1PRMWIP27E94kbeg5Zr5gN90':
                user.plan = 'standard_annual'
            elif price_id == 'price_1PRMVxP27E94kbeg7VJu5d2n':
                user.plan = 'premium_annual'

            db.session.commit()
            print("Plano do usuário atualizado")
        else:
            print("Usuário não encontrado")
    elif event['type'] == 'customer.subscription.deleted' or event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        customer_id = subscription['customer']

        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            if subscription['status'] == 'canceled':
                user.plan = 'free'
                user.stripe_subscription_id = None
                db.session.commit()
                print(f"Plano do usuário {user.email} atualizado para 'free'")

    else:
        print(f"Evento não tratado: {event['type']}")

    return jsonify(success=True)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify(success=False, error="CSRF token is missing or incorrect."), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
