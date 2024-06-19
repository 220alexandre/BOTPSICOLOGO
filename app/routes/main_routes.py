from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from flask_login import login_required, current_user
from app.models import db, Company, User
import requests
import json
from app.extensions import limiter

bp = Blueprint('main_routes', __name__)

@bp.route('/')
def home():
    return render_template('index.html')

@bp.route('/profile', methods=['GET', 'POST'])
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

@bp.route('/chat', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')

        # Definição do limite de tokens por plano
        plan_limits = {
            'free': 300,
            'standard': 5000,
            'premium': 10000,
            'standard_annual': 5000,
            'premium_annual': 10000
        }

        # Verificação do plano do usuário ou da empresa
        if current_user.company_id:
            company = Company.query.get(current_user.company_id)
            total_limit = plan_limits.get(current_user.plan, 0) + company.token_limit
            token_usage = company.current_token_usage
        else:
            total_limit = plan_limits.get(current_user.plan, 0) + current_user.token_limit
            token_usage = current_user.token_usage

        if token_usage >= total_limit:
            return jsonify({"error": "Token limit exceeded for your plan."})

        # Acessar a API_KEY do aplicativo Flask
        api_key = current_app.config['API_KEY']
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        # Corpo da mensagem
        body_msg = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "user", "content": user_message}
            ]
        }

        link = 'https://api.openai.com/v1/chat/completions'
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

@bp.route('/plans')
@login_required
def plans():
    return render_template('plans.html')
