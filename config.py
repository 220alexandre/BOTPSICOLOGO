import os
class Config:
    SECRET_KEY = "ad02dee34c4c68c1853e113b789cbca58218094918634cdd9d3dc1b9e8854538"
    SQLALCHEMY_DATABASE_URI = "mysql://root:@localhost/bot_local"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_KEY = "sk-proj-O2J7rJRTy5p7OWmcZOI3T3BlbkFJIxFhh996uxgVm9vHQiQi"
    STRIPE_SECRET_KEY = 'sk_test_51PRLgsP27E94kbegd3wyvDTbMdxrzaLBk8583Uv687a7XuMCMk6ufOKagOWPAWvqZCfjAN3m9WIAN1fl72KR1QOt00Urem1yzm'
    STRIPE_PUBLISHABLE_KEY = 'pk_test_51PRLgsP27E94kbegvyhLBnVkafXYkQjXl6o1jIjGlbV2TcWPGHz3Ll2DDuWzTca2TpIuCIeGJu5oczXJihMr6fFE00Nz2jDusZ'
    STRIPE_WEBHOOK_SECRET = 'whsec_vBzwmdnXqaRBZtjHyeYMkxOAAZKYSc8t'
    REDIS_URL = "redis://localhost:6379/0"