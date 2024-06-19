from app.models import db, User

def reset_token_usage():
    with app.app_context():
        users = User.query.all()
        for user in users:
            user.token_usage = 0
        db.session.commit()
        print("Token usage reset for all users.")
