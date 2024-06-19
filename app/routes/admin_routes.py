from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app.models import db, Company, CustomPlan, Employee, User

bp = Blueprint('admin_routes', __name__)

@bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('main_routes.home'))
    users = User.query.all()
    companies = Company.query.all()
    employees = Employee.query.all()
    return render_template('admin_dashboard.html', users=users, companies=companies, employees=employees)

@bp.route('/admin/create_company', methods=['GET', 'POST'])
@login_required
def create_company():
    if not current_user.is_admin:
        return redirect(url_for('main_routes.home'))
    if request.method == 'POST':
        name = request.form.get('name')
        user_limit = request.form.get('user_limit')
        token_limit = request.form.get('token_limit')
        new_company = Company(name=name, user_limit=user_limit, token_limit=token_limit)
        db.session.add(new_company)
        db.session.commit()
        flash('Company created successfully')
        return redirect(url_for('admin_routes.admin_dashboard'))
    return render_template('create_company.html')

@bp.route('/admin/create_custom_plan', methods=['GET', 'POST'])
@login_required
def create_custom_plan():
    if not current_user.is_admin:
        return redirect(url_for('main_routes.home'))
    if request.method == 'POST':
        company_id = request.form.get('company_id')
        price = request.form.get('price')
        tokens_per_user = request.form.get('tokens_per_user')
        new_plan = CustomPlan(company_id=company_id, price=price, tokens_per_user=tokens_per_user)
        db.session.add(new_plan)
        db.session.commit()
        flash('Custom plan created successfully')
        return redirect(url_for('admin_routes.admin_dashboard'))
    companies = Company.query.all()
    return render_template('create_custom_plan.html', companies=companies)

@bp.route('/admin/manage_company/<int:company_id>', methods=['GET', 'POST'])
@login_required
def manage_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('main_routes.home'))
    
    company = Company.query.get_or_404(company_id)
    return render_template('manage_company.html', company=company)

@bp.route('/admin/remove_employee/<int:employee_id>', methods=['POST'])
@login_required
def remove_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    if not current_user.is_admin:
        flash("Você não tem permissão para remover este empregado.")
        return redirect(url_for('main_routes.profile'))

    db.session.delete(employee)
    db.session.commit()
    flash("Empregado removido com sucesso.")
    return redirect(url_for('main_routes.profile'))

@bp.route('/admin/company/<int:company_id>/employees', methods=['GET', 'POST'])
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

@bp.route('/admin/update_company/<int:company_id>', methods=['POST'])
@login_required
def update_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('main_routes.home'))
    
    company = Company.query.get_or_404(company_id)
    company.plan = request.form.get('plan')
    company.token_limit = request.form.get('token_limit')
    company.monthly_cost = request.form.get('monthly_cost')
    db.session.commit()
    
    flash('Empresa atualizada com sucesso.')
    return redirect(url_for('admin_routes.manage_company', company_id=company_id))

@bp.route('/admin/delete_company/<int:company_id>', methods=['POST'])
@login_required
def delete_company(company_id):
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('main_routes.home'))
    
    company = Company.query.get_or_404(company_id)
    db.session.delete(company)
    db.session.commit()
    
    flash('Empresa deletada com sucesso.')
    return redirect(url_for('admin_routes.admin_dashboard'))

@bp.route('/admin/add_employee', methods=['POST'])
@login_required
def add_employee():
    if not current_user.is_admin:
        flash('Acesso negado. Somente administradores podem acessar esta página.')
        return redirect(url_for('main_routes.home'))

    name = request.form.get('name')
    email = request.form.get('email')
    company_id = request.form.get('company_id')
    existing_employee = Employee.query.filter_by(email=email).first()
    if existing_employee:
        flash('Funcionário com este email já existe.')
    else:
        new_employee = Employee(name=name, email=email, company_id=company_id)
        db.session.add(new_employee)
        db.session.commit()
        flash('Funcionário adicionado com sucesso.')

    return redirect(url_for('admin_routes.manage_employees', company_id=company_id))
