from flask import Blueprint, request, jsonify, url_for, current_app
from flask_login import login_required, current_user
from app.models import db, Company, User
from app.extensions import csrf
import stripe
import json

bp = Blueprint('stripe', __name__)

@bp.before_app_request
def setup_stripe():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']

@bp.route('/create-checkout-session', methods=['POST'])
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
            success_url=url_for('main.profile', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('main.profile', _external=True),
            customer_email=current_user.email
        )
        return jsonify({'id': session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@bp.route('/webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = current_app.config['STRIPE_WEBHOOK_SECRET']

    print("Recebido webhook com payload:", payload)

    event = None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        # Invalid payload
        print("Payload inválido.")
        return jsonify(success=False), 400
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        print("Assinatura inválida.")
        return jsonify(success=False), 400

    print("Evento recebido:", event)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_email = session['customer_details']['email']
        subscription_id = session.get('subscription')
        payment_status = session['payment_status']

        print("Detalhes da sessão:", session)
        print("Email do cliente:", customer_email)
        print("ID da assinatura:", subscription_id)
        print("Status do pagamento:", payment_status)

        user = User.query.filter_by(email=customer_email).first()
        if user:
            print("Usuário encontrado:", user.email)
            if subscription_id:
                # Atualizar assinatura do plano
                user.stripe_subscription_id = subscription_id
                subscription = stripe.Subscription.retrieve(subscription_id)
                plan_id = subscription['items']['data'][0]['price']['id']

                print("ID do plano:", plan_id)

                # Mapear os IDs dos preços para os planos
                plan_mapping = {
                    'price_1PRMVQP27E94kbegI68UwEpB': 'standard',  # Adicione o ID correto
                    'price_1PRMV8P27E94kbegb9WLZxk9': 'premium',  # Exemplo
                    'price_1PRMWIP27E94kbeg5Zr5gN90': 'standard_annual',  # Exemplo
                    'price_1PRMVxP27E94kbeg7VJu5d2n': 'premium_annual'  # Exemplo
                }

                user.plan = plan_mapping.get(plan_id, 'free')  # Definir o plano baseado no ID do preço
                print("Plano do usuário atualizado para:", user.plan)
            else:
                # Processar compra de tokens adicionais
                line_items = stripe.checkout.Session.list_line_items(session['id'])
                for item in line_items['data']:
                    if item['price']['id'] == 'price_1PSQCuP27E94kbegz3NhRFFi':
                        token_amount = 1000
                    elif item['price']['id'] == 'price_1PSQDEP27E94kbegwZzaexUf':
                        token_amount = 10000
                    else:
                        token_amount = 0

                    if user.company_id:
                        company = Company.query.get(user.company_id)
                        company.token_limit += token_amount
                        print(f"Tokens adicionados à empresa {company.name}: {token_amount}")
                    else:
                        user.token_limit += token_amount  # Adiciona tokens ao saldo disponível
                        print(f"Tokens adicionados ao usuário {user.email}: {token_amount}")
            db.session.commit()
            print("Dados do usuário atualizados no banco de dados.")
        else:
            print("Usuário não encontrado com o email:", customer_email)
    return jsonify(success=True)
