import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv
from database import db, bcrypt, login_manager
from flask_login import current_user, login_user, logout_user, login_required
from sqlalchemy import func, desc

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def create_app():
    load_dotenv()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_secreta_padrao')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'

    # Import de modelos após inicialização para evitar circular imports
    with app.app_context():
        from database.models import User, Course, Video, Enrollment, CTF, CTFScore

    @login_manager.user_loader
    def load_user(user_id):
        from database.models import User
        return db.session.get(User, int(user_id))

    # -------- rotas públicas --------
    @app.route('/')
    @app.route('/home')
    def home():
        return render_template('index.html')

    # -------- auth --------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        from database.models import User
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                flash('Login bem-sucedido!', 'success')
                return redirect(url_for('dashboard'))
            flash('Login falhou. Verifique suas credenciais.', 'danger')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        from database.models import User
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            if not (username and email and password):
                flash('Preencha todos os campos.', 'warning')
                return redirect(url_for('register'))
            if User.query.filter((User.username==username)|(User.email==email)).first():
                flash('Usuário ou email já existe.', 'danger')
                return redirect(url_for('register'))
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed, user_type='aluno')
            db.session.add(user); db.session.commit()
            flash('Conta criada! Faça login.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Você saiu da sessão.', 'info')
        return redirect(url_for('home'))

    # -------- dashboard --------
    @app.route('/dashboard')
    @login_required
    def dashboard():
        if current_user.user_type == 'admin':
            return render_template('dashboard_admin.html')
        elif current_user.user_type == 'professor':
            return render_template('dashboard_professor.html')
        else:
            return render_template('dashboard_aluno.html')

    # -------- cursos --------
    @app.route('/courses')
    def courses():
        from database.models import Course
        all_courses = Course.query.all()
        return render_template('courses.html', courses=all_courses)

    @app.route('/courses/<int:course_id>/enroll')
    @login_required
    def enroll_course(course_id):
        from database.models import Course, Enrollment
        course = Course.query.get_or_404(course_id)
        if current_user.user_type not in ['aluno', 'admin', 'professor']:
            flash('Apenas alunos podem se inscrever em cursos.', 'warning')
            return redirect(url_for('courses'))
        if Enrollment.query.filter_by(student_id=current_user.id, course_id=course.id).first():
            flash('Você já está inscrito neste curso.', 'info')
            return redirect(url_for('watch_course', course_id=course.id))
        new_enroll = Enrollment(student_id=current_user.id, course_id=course.id, progress=0)
        db.session.add(new_enroll); db.session.commit()
        flash('Inscrição realizada!', 'success')
        return redirect(url_for('watch_course', course_id=course.id))

    @app.route('/my_courses')
    @login_required
    def my_courses():
        from database.models import Enrollment
        enrolled = Enrollment.query.filter_by(student_id=current_user.id).all()
        return render_template('my_courses.html', enrolled_courses=enrolled)

    @app.route('/courses/<int:course_id>/watch')
    @login_required
    def watch_course(course_id):
        from database.models import Course, Enrollment
        course = Course.query.get_or_404(course_id)
        enrollment = Enrollment.query.filter_by(student_id=current_user.id, course_id=course.id).first()
        if not enrollment:
            flash('Inscreva-se para assistir ao curso.', 'warning')
            return redirect(url_for('courses'))
        videos = course.videos
        return render_template('watch_video.html', course=course, videos=videos)

    # -------- professores/admin --------
    def is_professor_or_admin():
        return current_user.is_authenticated and current_user.user_type in ['professor', 'admin']

    @app.route('/professor/my_courses')
    @login_required
    def professor_courses():
        from database.models import Course
        if not is_professor_or_admin():
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
        if current_user.user_type == 'professor':
            courses = Course.query.filter_by(professor_id=current_user.id).all()
        else:
            courses = Course.query.all()
        return render_template('courses.html', courses=courses)

    @app.route('/course/create', methods=['GET', 'POST'])
    @login_required
    def create_course():
        from database.models import Course
        if not is_professor_or_admin():
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            if not title or not description:
                flash('Preencha título e descrição.', 'warning')
                return render_template('create_course.html')
            new_course = Course(title=title, description=description, professor_id=current_user.id)
            db.session.add(new_course); db.session.commit()
            flash('Curso criado!', 'success')
            return redirect(url_for('manage_videos', course_id=new_course.id))
        return render_template('create_course.html')

    @app.route('/course/<int:course_id>/manage_videos', methods=['GET', 'POST'])
    @login_required
    def manage_videos(course_id):
        from database.models import Course, Video
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para este curso.', 'danger')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            video_title = request.form.get('video_title')
            video_url = request.form.get('video_url')
            try:
                video_order = int(request.form.get('video_order'))
            except:
                video_order = 0
            if not (video_title and video_url):
                flash('Preencha todos os campos do vídeo.', 'warning')
            else:
                v = Video(title=video_title, video_url=video_url, order_in_course=video_order, course_id=course.id)
                db.session.add(v); db.session.commit()
                flash('Vídeo adicionado!', 'success')
            return redirect(url_for('manage_videos', course_id=course.id))
        videos = course.videos
        return render_template('manage_videos.html', course=course, videos=videos)

    @app.route('/course/<int:course_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_course(course_id):
        from database.models import Course
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            course.title = request.form.get('title')
            course.description = request.form.get('description')
            db.session.commit()
            flash('Curso atualizado!', 'success')
            return redirect(url_for('manage_videos', course_id=course.id))
        return render_template('edit_course.html', course=course)

    @app.route('/course/delete/<int:course_id>', methods=['GET' , 'POST'])
    @login_required
    def delete_course(course_id):
        from database.models import Course
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
        try:
            db.session.delete(course); db.session.commit()
            flash('Curso deletado com sucesso!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar: {e}', 'danger')
        return redirect(url_for('professor_courses'))

    # -------- CTFs --------
    @app.route('/ctfs')
    @login_required
    def ctfs():
        from database.models import CTF
        challenges = CTF.query.all()
        return render_template('ctfs.html', challenges=challenges)

    @app.route('/ctfs/create', methods=['GET', 'POST'])
    @login_required
    def create_ctf():
        from database.models import CTF
        if current_user.user_type not in ['admin', 'professor']:
            flash('Apenas admin/professor pode criar CTF.', 'danger')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            difficulty = request.form.get('difficulty')
            points = int(request.form.get('points') or 0)
            flag_plain = request.form.get('flag')
            ctf = CTF(title=title, description=description, difficulty=difficulty, points=points)
            ctf.set_flag(flag_plain)
            db.session.add(ctf); db.session.commit()
            flash('CTF criado!', 'success')
            return redirect(url_for('ctfs'))
        return render_template('create_ctf.html')

    @app.route('/ctfs/<int:ctf_id>', methods=['GET', 'POST'])
    @login_required
    def ctf_challenge(ctf_id):
        from database.models import CTF, CTFScore
        challenge = CTF.query.get_or_404(ctf_id)
        if request.method == 'POST':
            user_flag = request.form.get('flag', '')
            if challenge.check_flag(user_flag):
                existing_score = CTFScore.query.filter_by(user_id=current_user.id, ctf_id=challenge.id).first()
                if not existing_score:
                    new_score = CTFScore(user_id=current_user.id, ctf_id=challenge.id, score=challenge.points)
                    db.session.add(new_score); db.session.commit()
                    flash(f'Flag correta! Você ganhou {challenge.points} pontos.', 'success')
                else:
                    flash('Você já resolveu este desafio.', 'info')
            else:
                flash('Flag incorreta. Tente novamente.', 'danger')
            return redirect(url_for('ctf_challenge', ctf_id=ctf_id))
        return render_template('ctf_challenge.html', challenge=challenge)

    @app.route('/ctf_ranking')
    @login_required
    def ctf_ranking():
        from database.models import User, CTFScore
        rows = db.session.query(
            User.username,
            func.sum(CTFScore.score).label('total_score')
        ).join(CTFScore, CTFScore.user_id == User.id).group_by(User.id).order_by(desc('total_score')).all()
        ranking = [{'username': r[0], 'total_score': int(r[1])} for r in rows]
        return render_template('ctf_ranking.html', ranking=ranking)

    return app

# For quick dev run
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
