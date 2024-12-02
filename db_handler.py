from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON)

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()

def add_vulnerability(data):
    with db.session.begin():
        new_record = Vulnerability(data=data)
        db.session.add(new_record)

def get_all_vulnerabilities():
    return Vulnerability.query.all()

def count_vulnerabilities():
    return Vulnerability.query.count()
