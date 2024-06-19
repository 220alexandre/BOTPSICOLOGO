from flask import Flask
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
from config import Config
from app.utils.token_reset import reset_token_usage
from app.extensions import db, login_manager, csrf, limiter
from app.models import User
from app.monitor import get_system_usage, system_usage

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth_routes.login'

    from app.routes import admin_routes, auth_routes, main_routes, stripe_routes
    app.register_blueprint(admin_routes.bp, name='admin_routes')
    app.register_blueprint(auth_routes.bp, name='auth_routes')
    app.register_blueprint(main_routes.bp, name='main_routes')
    app.register_blueprint(stripe_routes.bp, name='stripe_routes')
    app.add_url_rule('/system_usage', 'system_usage', system_usage)
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=reset_token_usage, trigger='cron', day=1, hour=0, minute=0, id='reset_token_usage', replace_existing=True)
    scheduler.start()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    return app
