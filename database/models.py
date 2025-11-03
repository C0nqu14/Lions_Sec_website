from datetime import datetime
import hashlib
from flask_login import UserMixin
from . import db
# from sqlalchemy.dialects.postgresql import JSON  # Manter se usar BD moderna, senão usar Text

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='aluno')  # aluno, professor, admin
    
    # NOVO: Caminho da imagem de perfil (avatar)
    image_file = db.Column(db.String(20), nullable=False, default='default_hacker.png')

    courses_taught = db.relationship('Course', backref='professor', lazy=True, cascade="all, delete")
    enrolled_courses = db.relationship('Enrollment', backref='student', lazy=True, cascade="all, delete")
    ctf_scores = db.relationship('CTFScore', backref='user', lazy=True, cascade="all, delete")

    def is_professor(self):
        return self.user_type == 'professor'

    def is_admin(self):
        return self.user_type == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # NOVO: Caminho da imagem do curso
    course_image = db.Column(db.String(40), nullable=False, default='default_course.png')
    # Adicionado campo de dificuldade que é usado no app.py
    difficulty = db.Column(db.String(20), nullable=True, default='Iniciante') 

    modules = db.relationship('Module', backref='course', lazy=True, order_by='Module.order_in_course', cascade="all, delete-orphan")
    enrollments = db.relationship('Enrollment', backref='course', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Course {self.title}>'


# NOVO MODELO: Module
class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    order_in_course = db.Column(db.Integer, nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    
    videos = db.relationship('Video', backref='module', lazy=True, order_by='Video.order_in_course', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Module {self.title}>'


class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    video_url = db.Column(db.String(300), nullable=False)
    order_in_course = db.Column(db.Integer, nullable=False) 
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    
    # NOVO: Campo de descrição do vídeo
    description = db.Column(db.Text, nullable=True) 

    def __repr__(self):
        return f'<Video {self.title}>'


class Enrollment(db.Model):
    __tablename__ = 'enrollment'
    __table_args__ = (db.UniqueConstraint('student_id', 'course_id', name='uq_student_course'),)

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    
    status = db.Column(db.String(20), nullable=False, default='PENDENTE')
    
    # 💥 LINHA CRÍTICA ADICIONADA: O Flask-SQLAlchemy usa UTC.
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now) 
    
    progress_data = db.Column(db.Text, default='{}') 
    progress_percent = db.Column(db.Integer, default=0)
    last_video_watched = db.Column(db.Integer, nullable=True) # ID do último vídeo visto


class CTF(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    flag_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hex
    points = db.Column(db.Integer, nullable=False)
    
    # NOVO: Campo para controlar quem criou (opcional, para futura expansão)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) 
    creator = db.relationship('User', backref='ctf_created')

    scores = db.relationship('CTFScore', backref='ctf', lazy=True, cascade="all, delete-orphan")

    def set_flag(self, flag: str):
        self.flag_hash = hashlib.sha256(flag.encode('utf-8')).hexdigest()

    def check_flag(self, attempt: str) -> bool:
        # Nota: O attempt deve ser a flag em texto simples, não o hash
        return hashlib.sha256(attempt.encode('utf-8')).hexdigest() == self.flag_hash

    def __repr__(self):
        return f'<CTF {self.title}>'


class CTFScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ctf_id = db.Column(db.Integer, db.ForeignKey('ctf.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now) # Corrigido para utcnow

# --- Fim de models.py ---