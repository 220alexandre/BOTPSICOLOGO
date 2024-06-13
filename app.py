import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from senha import SECRET_KEY, SQLALCHEMY_DATABASE_URI, API_KEY

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    plan = db.Column(db.String(50), nullable=False, default='free')
    token_usage = db.Column(db.Integer, nullable=False, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# URL do endpoint da OpenAI
link = 'https://api.openai.com/v1/chat/completions'

# Cabeçalhos da requisição
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Instrução do sistema detalhada
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
    "Use the uploaded file's tables of suggested words, feelings, thoughts, observations, and requests to guide users on how to express themselves effectively. Before offering suggestions and teaching about assertive communication and NVC, encourage users to share more details about their doubts, emotions and situações and use the information provided to adapt the guidance. "
    "Invest in more questions than affirmative or directive responses initially. When the user presents their issue, ask variations of: 'How would you feel most helped by me?' Offer options such as: explaining concepts, guiding word changes until the user feels satisfied, communication exercises, and more. When asking for information, confirm if the user has finished answering the questions to ensure complete responses. Always ask before providing information to foster empathy. "
    "Provide one piece of information at a time, checking if the user understood or has any questions, and encourage writing to practice. Incorporate the content from the uploaded books, using relevant examples and insights from them to further enrich the guidance provided. Follow a non-directive approach in responding to requests, asking more questions and teaching only if explicitly requested by the user. Explain topics one at a time and ask for feedback to ensure understanding, encouraging writing exercises if helpful. "
    "When discussing topics, address one aspect at a time and save the response for later use before moving to the next topic. Always ask more questions before offering a solution, guidance, instruction, or exercise. Provide small, manageable solutions, instructions, or exercises, and always ask for feedback to ensure the user is comprehending. When the user explains what they want, respond with empathy for their situation and ask how they think you can help: 'We can give examples of dialogues, teach you how to communicate assertively with exercises and/or just enrich you theoretically with the most fundamental concepts for this purpose.' "
    "Address one topic at a time to develop the user's mindset gradually. Limit responses to 500 characters. In the initial responses, focus on more questions, saving answers for precise help. Address one concept at a time with few questions. Ask before offering a solution. In the end, suggest the attached videos as a content suggestion and the books as well."
)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
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

@app.route('/register', methods=['GET', 'POST'])
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
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')
        print(f"Recebido do usuário: {user_message}")

        # Verificação do plano do usuário
        plan_limits = {'free': 200,'normal': 1000, 'premium': 5000, 'unlimited': float('inf')}
        if current_user.token_usage >= plan_limits[current_user.plan]:
            return jsonify({"error": "Voce chegou ao limite de tokens. Por favor, atualize seu plano."})

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
