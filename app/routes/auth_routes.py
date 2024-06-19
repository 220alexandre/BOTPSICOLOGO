from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User
from app.extensions import limiter
from datetime import datetime
import stripe
bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main_routes.chat'))
        else:
            flash('Login failed. Check your email and password.')
    return render_template('login.html')

@bp.route('/register', methods=['GET', 'POST'])
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
        return redirect(url_for('main_routes.chat'))
    return render_template('register.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

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

@bp.route('/cancel_subscription', methods=['POST'])
@login_required
def cancel_subscription():
    if current_user.stripe_subscription_id:
        try:
            # Cancelar a assinatura
            subscription = stripe.Subscription.delete(current_user.stripe_subscription_id)
            print(f"Subscription status after deletion: {subscription['status']}")

            # Verificar se um reembolso é necessário
            if subscription['status'] == 'active':
                # Encontrar a última fatura paga
                invoices = stripe.Invoice.list(
                    subscription=current_user.stripe_subscription_id,
                    limit=1
                )
                print(f"Invoices found: {invoices['data']}")

                if invoices['data']:
                    last_invoice = invoices['data'][0]
                    print(f"Last invoice: {last_invoice}")

                    # Processar o reembolso
                    refund = stripe.Refund.create(
                        charge=last_invoice['charge']
                    )
                    print(f"Refund processed: {refund}")

            current_user.stripe_subscription_id = None
            current_user.plan = 'free'
            db.session.commit()
            print("User subscription and plan updated in database.")
            flash('Assinatura cancelada com sucesso e reembolso processado.')
            print('Assinatura cancelada com sucesso e reembolso processado.')
        except stripe.error.StripeError as e:
            print(f"Stripe error: {str(e)}")
            flash(f'Ocorreu um erro ao cancelar a assinatura: {str(e)}')
    else:
        print("User does not have a stripe_subscription_id.")
    return redirect(url_for('main_routes.profile'))

@bp.route('/remove_employee/<int:employee_id>', methods=['POST'])
@login_required
def remove_employee(employee_id):
    employee = User.query.get_or_404(employee_id)
    if current_user.company_id != employee.company_id:
        flash('Você não tem permissão para remover este empregado.')
        return redirect(url_for('main_routes.profile'))

    db.session.delete(employee)
    db.session.commit()
    flash('Empregado removido com sucesso.')
    return redirect(url_for('main_routes.profile'))