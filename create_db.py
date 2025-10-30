from app import create_app
from database import db, bcrypt
from database.models import User, CTF

app = create_app()
with app.app_context():
    db.drop_all()
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin_password = bcrypt.generate_password_hash('password123').decode('utf-8')
        admin = User(username='admin', email='admin@lions.sec', password=admin_password, user_type='admin')
        db.session.add(admin)
        print("Usuário Admin criado. Login: admin / password123")

    if not User.query.filter_by(username='joao_conquia').first():
        prof_password = bcrypt.generate_password_hash('professor123').decode('utf-8')
        professor = User(username='joao_conquia', email='joao@lions.sec', password=prof_password, user_type='professor')
        db.session.add(professor)
        print("Professor criado: joao_conquia / professor123")

    if not CTF.query.first():
        c1 = CTF(title="Desafio Web Básico", difficulty="Fácil", description="Encontre a flag no código-fonte desta página.", points=100)
        c1.set_flag("LIONS_SEC{welcome_to_cyber_world}")
        c2 = CTF(title="Análise de Rede", difficulty="Médio", description="Analise o pcap e ache a flag.", points=250)
        c2.set_flag("LIONS_SEC{packets_dont_lie}")
        db.session.add_all([c1, c2])

    db.session.commit()
    print("Banco de dados e seeds criados com sucesso!")
