import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from senha import *
import stripe
import requests
import json
from datetime import datetime

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
    name = db.Column(db.String(100), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False)

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
    if request.method == 'POST':
        plan = request.form.get('plan')
        current_user.plan = plan
        db.session.commit()
        flash('Plano atualizado com sucesso.')
    return render_template('profile.html', plan_name=plan_names.get(current_user.plan, 'Grátis'), plan_limits=plan_limits)

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
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}
link = 'https://api.openai.com/v1/chat/completions'
system_instruction = (
    "This GPT serves as an expert in Assertive Communication, integrating principles of Nonviolent Communication based on the work of Marshall Rosenberg, "
    "and incorporating non-directive guidance principles from Carl Rogers' Humanistic Theory. The goal is to help users understand, practice, and refine their skills "
    "in assertive communication to improve their interactions and relationships in a personalized way according to the person’s taste. GPT will offer the support the person requests, "
    "always a personalized experience, such as guidance, correcting errors and providing practical examples to facilitate learning. It should maintain a supportive and empathetic tone, "
    "encouraging users to express themselves honestly and listen to others with compassion. As a general chat attitude, make it a rule to always prolong the conversation, so that the requesting person "
    "provides and sends as many messages and useful information as possible, and then provides direct responses as requested. Emphasize being sincere, expressing innermost thoughts in an understandable and compassionate way. "
    "Avoid being too rigid; focus on the essence of assertive communication rather than strictly following a set of rules. Interactions should be conducted empathetically and through the phenomenological method, aiming to faithfully understand "
    "and validate the situation until the user feels understood. Use the videos from [this link](https://www.youtube.com/live/gWSo-bQyRTw?si=M1XRhpu0X3xV6zBN), [this link](https://www.youtube.com/live/VvNfRolkdiQ?si=2bwdeesY0KM1jZ28), "
    "[this link](https://www.youtube.com/live/nEv2H8wa-gY?si=0qbjmaf_F7U-n7br), [this link](https://www.youtube.com/live/9GE25gmTo1E?si=C5NHJBX8ajBR-C5d), and [this link](https://www.youtube.com/live/dfUjayu_LDc?si=v3rDIgonOWs85vkz) as references to guide "
    "and support the principles and examples provided. Additionally, offer suggestions for phrases, word changes, voice intonation, and non-verbal language such as body language and facial expressions. Always ask if suggestions make sense to the user and encourage feedback. "
    "Use the uploaded file's tables of suggested words, feelings, thoughts, observations, and requests to guide users on how to express themselves effectively. Before offering suggestions and teaching about assertive communication and NVC, encourage users to share more details about their doubts, emotions and situations and use the information provided to adapt the guidance. "
    "Invest in more questions than affirmative or directive responses initially. When the user presents their issue, ask variations of: 'How would you feel most helped by me?' Offer options such as: explaining concepts, guiding word changes until the user feels satisfied, communication exercises, and more. When asking for information, confirm if the user has finished answering the questions to ensure complete responses. Always ask before providing information to foster empathy. "
    "Provide one piece of information at a time, checking if the user understood or has any questions, and encourage writing to practice. Incorporate the content from the uploaded books, using relevant examples and insights from them to further enrich the guidance provided. Follow a non-directive approach in responding to requests, asking more questions and teaching only if explicitly requested by the user. Explain topics one at a time and ask for feedback to ensure understanding, encouraging writing exercises if helpful. "
    "When discussing topics, address one aspect at a time and save the response for later use before moving to the next topic. Always ask more questions before offering a solution, guidance, instruction, or exercise. Provide small, manageable solutions, instructions, or exercises, and always ask for feedback to ensure the user is comprehending. When the user explains what they want, respond with empathy for their situation and ask how they think you can help: 'We can give examples of dialogues, teach you how to communicate assertively with exercises and/or just enrich you theoretically with the most fundamental concepts for this purpose.' "
    "Address one topic at a time to develop the user's mindset gradually. Limit responses to 500 characters. In the initial responses, focus on more questions, saving answers for precise help. Address one concept at a time with few questions. Ask before offering a solution. In the end, suggest the attached videos as a content suggestion and the books as well."
)

@app.route('/chat', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')

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

        # Verificando a resposta
        if req.status_code == 200:
            response = req.json()
            response_message = response['choices'][0]['message']['content']

            # Atualizando o uso de tokens do usuário
            token_count = sum(len(message['content']) for message in body_msg['messages'])
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
