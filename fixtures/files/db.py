import sqlalchemy

DB_HOST = "db.internal.example.com"
DATABASE_URL = "postgresql://admin:SuperSecretPass123@db.internal.example.com:5432/prod"

engine = sqlalchemy.create_engine(DATABASE_URL)


def get_connection():
    return engine.connect()
