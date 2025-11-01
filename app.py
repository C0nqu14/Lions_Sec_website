import os
import hashlib
import json 
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv
from database import db, bcrypt, login_manager
from flask_login import current_user, login_user, logout_user, login_required
from sqlalchemy import func, desc, asc 
from functools import wraps # Importação necessária para decoradores

# Função de hash SHA256 (mantida para a lógica CTF)
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
        # Certifique-se de que todos os modelos estão importados (necessário para a query de ranking)
        from database.models import User, Course, Video, Module, Enrollment, CTF, CTFScore

    @login_manager.user_loader
    def load_user(user_id):
        from database.models import User
        return db.session.get(User, int(user_id))
    
    # Funções de Auxílio e Decoradores
    def is_professor_or_admin():
        return current_user.is_authenticated and current_user.user_type in ['professor', 'admin']

    def professor_or_admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_professor_or_admin():
                flash('Acesso não autorizado. Você precisa ser um Professor ou Administrador.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
        
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

    # -------- Perfil do Usuário (NOVA ROTA) --------
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        from database.models import User
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            
            if not username or not email:
                flash('Nome de usuário e email são obrigatórios.', 'warning')
                return redirect(url_for('edit_profile'))
            
            # Checar se o novo username/email já existe (excluindo o próprio usuário)
            user_exists = User.query.filter(
                (User.username == username) | (User.email == email),
                User.id != current_user.id
            ).first()
            
            if user_exists:
                flash('Nome de usuário ou email já em uso por outro usuário.', 'danger')
                return redirect(url_for('edit_profile'))
            
            current_user.username = username
            current_user.email = email
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        return render_template('edit_profile.html')
        
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

    # -------- cursos (ALUNO VIEW) --------
    @app.route('/courses')
    def courses():
        from database.models import Course, Enrollment
        all_courses = Course.query.all()
        
        user_enrollments = {}
        if current_user.is_authenticated:
            enrolled = Enrollment.query.filter_by(student_id=current_user.id).all()
            enrolled_ids = {e.course_id: e.status for e in enrolled} # Mapeia ID do curso para o status
            
            for course in all_courses:
                # Se for professor/admin e o curso for dele, permite acesso (PROFESSOR)
                if course.professor_id == current_user.id and current_user.user_type in ['professor', 'admin']:
                    user_enrollments[course.id] = 'PROFESSOR'
                # Se estiver inscrito, mostra o status (PENDENTE/AUTORIZADO/REJEITADO)
                elif course.id in enrolled_ids:
                    user_enrollments[course.id] = enrolled_ids[course.id] 
                # Se não, mostra NONE (para botão de Inscrição)
                else:
                    user_enrollments[course.id] = 'NONE'

        return render_template('courses.html', courses=all_courses, user_enrollments=user_enrollments)


    @app.route('/courses/<int:course_id>/enroll')
    @login_required
    def enroll_course(course_id):
        from database.models import Course, Enrollment
        course = Course.query.get_or_404(course_id)
        
        if current_user.user_type != 'aluno':
            flash('Apenas alunos podem solicitar inscrição.', 'warning')
            return redirect(url_for('courses'))
        
        # Prevenção de Bug: Professor não se inscreve no próprio curso
        if course.professor_id == current_user.id:
            flash('Você é o criador deste curso e não pode se inscrever.', 'warning')
            return redirect(url_for('manage_course', course_id=course.id)) 

        existing_enrollment = Enrollment.query.filter_by(student_id=current_user.id, course_id=course.id).first()

        if existing_enrollment:
            if existing_enrollment.status == 'AUTORIZADO':
                flash('Você já está autorizado neste curso.', 'info')
                return redirect(url_for('watch_course', course_id=course.id))
            elif existing_enrollment.status == 'PENDENTE':
                flash('Sua inscrição está PENDENTE de aprovação do administrador.', 'warning')
                return redirect(url_for('courses'))
            # Se for REJEITADO, a lógica abaixo irá sobrescrever para PENDENTE (nova tentativa)
            
        # Cria-se PENDENTE (ou sobrescreve REJEITADO)
        if existing_enrollment:
            existing_enrollment.status = 'PENDENTE'
            db.session.commit()
        else:
            new_enroll = Enrollment(student_id=current_user.id, course_id=course.id, status='PENDENTE')
            db.session.add(new_enroll); db.session.commit()
            
        flash('Inscrição enviada! O Administrador deve autorizá-la.', 'success')
        return redirect(url_for('courses'))


    @app.route('/courses/<int:course_id>/watch', defaults={'video_id': None})
    @app.route('/courses/<int:course_id>/watch/<int:video_id>')
    @login_required
    def watch_course(course_id, video_id):
        from database.models import Course, Enrollment, Video
        course = Course.query.get_or_404(course_id)

        enrollment = Enrollment.query.filter_by(student_id=current_user.id, course_id=course.id).first()
        
        is_owner = current_user.user_type == 'admin' or course.professor_id == current_user.id
        
        # VERIFICAÇÃO DE AUTORIZAÇÃO
        if not is_owner and (not enrollment or enrollment.status != 'AUTORIZADO'):
            flash('Sua inscrição não está AUTORIZADA. Contate o administrador.', 'warning')
            return redirect(url_for('courses'))
        
        # Módulos são obtidos automaticamente pela relação no modelo Course
        modules = course.modules 
        current_video = None
        
        # Lógica de determinar o vídeo inicial
        if video_id:
            video_to_watch = Video.query.get(video_id)
            # Verifica se o vídeo existe e pertence ao curso via módulo
            if video_to_watch and video_to_watch.module and video_to_watch.module.course_id == course.id:
                current_video = video_to_watch
            else:
                 flash('Vídeo não encontrado ou não pertence a este curso.', 'danger')
        
        # Se não encontrou o vídeo por ID, tenta o primeiro vídeo do primeiro módulo
        if not current_video and modules and modules[0].videos:
             current_video = modules[0].videos[0]
        
        # TODO: Lógica de atualização de progresso viria aqui

        return render_template('watch_video.html', 
                               course=course, 
                               modules=modules,
                               current_video=current_video)

    @app.route('/my_courses')
    @login_required
    def my_courses():
        from database.models import Enrollment
        # Filtra apenas cursos AUTORIZADOS
        enrolled = Enrollment.query.filter_by(student_id=current_user.id, status='AUTORIZADO').all()
        return render_template('my_courses.html', enrolled_courses=enrolled)


    # -------- PROFESSOR/ADMIN Rotas de Gestão DE CONTEÚDO --------
    
    @app.route('/professor/my_courses')
    @professor_or_admin_required
    def professor_courses():
        from database.models import Course
        if current_user.user_type == 'professor':
            courses = Course.query.filter_by(professor_id=current_user.id).all()
        else: # Admin vê todos
            courses = Course.query.all()
            
        return render_template('professor_courses.html', courses=courses) 

    @app.route('/course/create', methods=['GET', 'POST'])
    @professor_or_admin_required
    def create_course():
        from database.models import Course
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            
            if not title or not description:
                flash('Preencha título e descrição.', 'warning')
                return render_template('create_course.html')
                
            new_course = Course(title=title, description=description, professor_id=current_user.id)
            db.session.add(new_course); db.session.commit()
            
            flash('Curso criado! Adicione módulos e vídeos em seguida.', 'success')
            # Redireciona para o novo painel de gestão modular
            return redirect(url_for('manage_course', course_id=new_course.id))
            
        return render_template('create_course.html')


    @app.route('/course/<int:course_id>/edit', methods=['GET', 'POST'])
    @professor_or_admin_required
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
            return redirect(url_for('manage_course', course_id=course.id))

        return render_template('edit_course.html', course=course)

    @app.route('/course/delete/<int:course_id>', methods=['POST'])
    @professor_or_admin_required
    def delete_course(course_id):
        from database.models import Course
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
            
        try:
            # O CASCADE deve tratar módulos e vídeos, mas deletamos o curso
            db.session.delete(course); db.session.commit()
            flash('Curso deletado com sucesso (Módulos e Vídeos associados também foram apagados)!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar: {e}', 'danger')
            
        return redirect(url_for('professor_courses'))


    @app.route('/course/<int:course_id>/manage', methods=['GET'])
    @professor_or_admin_required
    def manage_course(course_id):
        from database.models import Course
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para este curso.', 'danger')
            return redirect(url_for('dashboard'))
            
        # Os módulos são carregados automaticamente (ordenados pela coluna 'order_in_course')
        return render_template('manage_course.html', course=course) 

    @app.route('/course/<int:course_id>/add_module', methods=['POST'])
    @professor_or_admin_required
    def add_module(course_id):
        from database.models import Course, Module
        course = Course.query.get_or_404(course_id)
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão.', 'danger')
            return redirect(url_for('dashboard'))
        
        title = request.form.get('module_title')
        try:
            order = int(request.form.get('module_order'))
        except (ValueError, TypeError):
            order = 999 

        if title:
            new_module = Module(title=title, order_in_course=order, course_id=course.id)
            db.session.add(new_module); db.session.commit()
            flash('Módulo criado com sucesso!', 'success')
        else:
            flash('O título do módulo não pode ser vazio.', 'warning')
            
        return redirect(url_for('manage_course', course_id=course_id))


    # ROTA DE EDIÇÃO DE MÓDULO
    @app.route('/module/<int:module_id>/edit', methods=['GET', 'POST'])
    @professor_or_admin_required
    def edit_module(module_id):
        from database.models import Module
        module = Module.query.get_or_404(module_id)
        course = module.course

        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para editar este módulo.', 'danger')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            module.title = request.form.get('module_title')
            try:
                module.order_in_course = int(request.form.get('module_order'))
            except (ValueError, TypeError):
                flash('Ordem deve ser um número válido.', 'warning')
                return redirect(url_for('edit_module', module_id=module.id))

            db.session.commit()
            flash('Módulo atualizado!', 'success')
            return redirect(url_for('manage_course', course_id=course.id))

        return render_template('edit_module.html', course=course, module=module)

    # ROTA DE DELEÇÃO DE MÓDULO
    @app.route('/module/delete/<int:module_id>', methods=['POST'])
    @professor_or_admin_required
    def delete_module(module_id):
        from database.models import Module
        module = Module.query.get_or_404(module_id)
        course = module.course

        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para deletar este módulo.', 'danger')
            return redirect(url_for('dashboard'))
        
        try:
            # O CASCADE deve tratar os vídeos, mas deletamos o módulo
            db.session.delete(module); db.session.commit()
            flash(f'Módulo "{module.title}" deletado com sucesso.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar: {e}', 'danger')
            
        return redirect(url_for('manage_course', course_id=course.id))


    @app.route('/module/<int:module_id>/manage_videos', methods=['GET', 'POST'])
    @professor_or_admin_required
    def manage_videos(module_id):
        from database.models import Module, Video
        module = Module.query.get_or_404(module_id)
        course = module.course 
        
        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para este módulo.', 'danger')
            return redirect(url_for('dashboard'))

        # Lógica de POST (Adicionar Novo Vídeo)
        if request.method == 'POST':
            video_title = request.form.get('video_title')
            video_url = request.form.get('video_url')
            try:
                video_order = int(request.form.get('video_order'))
            except (ValueError, TypeError):
                video_order = 0
            
            if video_title and video_url:
                v = Video(title=video_title, video_url=video_url, order_in_course=video_order, module_id=module.id)
                db.session.add(v); db.session.commit()
                flash('Vídeo adicionado!', 'success')
            else:
                 flash('Preencha título e URL do vídeo.', 'warning')
                 
            return redirect(url_for('manage_videos', module_id=module.id))
            
        videos = module.videos 

        return render_template('manage_videos.html', course=course, module=module, videos=videos)
        

    # ROTA DE EDIÇÃO DE VÍDEO
    @app.route('/video/<int:video_id>/edit', methods=['GET', 'POST'])
    @professor_or_admin_required
    def edit_video(video_id):
        from database.models import Video
        video = Video.query.get_or_404(video_id)
        module = video.module
        course = module.course

        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para editar este vídeo.', 'danger')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            video.title = request.form.get('video_title')
            video.video_url = request.form.get('video_url')
            try:
                video.order_in_course = int(request.form.get('video_order'))
            except (ValueError, TypeError):
                flash('Ordem deve ser um número válido.', 'warning')
                return redirect(url_for('edit_video', video_id=video.id))

            db.session.commit()
            flash('Vídeo atualizado!', 'success')
            return redirect(url_for('manage_videos', module_id=module.id))

        return render_template('edit_video.html', course=course, module=module, video=video)

    # ROTA DE DELEÇÃO DE VÍDEO
    @app.route('/video/delete/<int:video_id>', methods=['POST'])
    @professor_or_admin_required
    def delete_video(video_id):
        from database.models import Video
        video = Video.query.get_or_404(video_id)
        module = video.module
        course = module.course

        if course.professor_id != current_user.id and current_user.user_type != 'admin':
            flash('Sem permissão para deletar este vídeo.', 'danger')
            return redirect(url_for('dashboard'))
        
        try:
            db.session.delete(video); db.session.commit()
            flash(f'Vídeo "{video.title}" deletado com sucesso.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar: {e}', 'danger')
            
        return redirect(url_for('manage_videos', module_id=module.id))

    # -------- CTFs --------
    @app.route('/ctfs')
    @login_required
    def ctfs():
        from database.models import CTF
        challenges = CTF.query.all()
        return render_template('ctfs.html', challenges=challenges)

    @app.route('/ctfs/create', methods=['GET', 'POST'])
    @professor_or_admin_required
    def create_ctf():
        from database.models import CTF
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

        
    @app.route('/ctfs/ranking')
    @login_required
    def ctf_ranking():
        from database.models import CTFScore, User, db
        
        ranking_data = db.session.query(
            User.username,
            func.sum(CTFScore.score).label('total_score')
        ).join(CTFScore, User.id == CTFScore.user_id).group_by(User.id, User.username).order_by(desc('total_score')).all()
        
        ranking = [{'username': r.username, 'total_score': int(r.total_score)} for r in ranking_data]
        
        return render_template('ctf_ranking.html', ranking=ranking)


    # -------- Rotas de ADMIN (Gestão de Utilizadores e Autorização) --------

    @app.route('/admin/users')
    @login_required
    def manage_users():
        from database.models import User
        if current_user.user_type != 'admin':
            flash('Sem permissão de administrador.', 'danger')
            return redirect(url_for('dashboard'))
        
        all_users = User.query.filter(User.id != current_user.id).all() # Não lista o próprio admin
        return render_template('admin/manage_users.html', users=all_users)

    @app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
    @login_required
    def delete_user(user_id):
        from database.models import User
        if current_user.user_type != 'admin':
            flash('Sem permissão de administrador.', 'danger')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(user_id)
        if user.user_type == 'admin':
            flash('Não é possível deletar outro administrador.', 'danger')
        else:
            db.session.delete(user); db.session.commit()
            flash(f'Usuário {user.username} deletado.', 'success')
            
        return redirect(url_for('manage_users'))

    @app.route('/admin/create_professor', methods=['GET', 'POST'])
    @login_required
    def create_professor():
        from database.models import User
        if current_user.user_type != 'admin':
            flash('Sem permissão de administrador.', 'danger')
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            if User.query.filter((User.username==username)|(User.email==email)).first():
                flash('Usuário ou email já existe.', 'danger')
                return render_template('admin/create_professor.html')

            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            professor = User(username=username, email=email, password=hashed, user_type='professor')
            db.session.add(professor); db.session.commit()
            flash(f'Professor {username} criado com sucesso!', 'success')
            return redirect(url_for('manage_users'))

        return render_template('admin/create_professor.html')
        

    @app.route('/admin/enrollments')
    @login_required
    def manage_enrollments():
        from database.models import Enrollment
        if current_user.user_type != 'admin':
            flash('Sem permissão de administrador.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Obter todas as pendentes e autorizadas para melhor gestão
        enrollments = Enrollment.query.order_by(asc(Enrollment.status)).all() 
        return render_template('admin/manage_enrollments.html', enrollments=enrollments)

    @app.route('/admin/enrollment/<int:enrollment_id>/<action>', methods=['POST'])
    @login_required
    def authorize_enrollment(enrollment_id, action):
        from database.models import Enrollment
        if current_user.user_type != 'admin':
            flash('Sem permissão de administrador.', 'danger')
            return redirect(url_for('dashboard'))
        
        enrollment = Enrollment.query.get_or_404(enrollment_id)
        
        if action == 'authorize':
            enrollment.status = 'AUTORIZADO'
            flash(f'Inscrição de {enrollment.student.username} no curso {enrollment.course.title} AUTORIZADA.', 'success')
        elif action == 'reject':
            enrollment.status = 'REJEITADO'
            flash(f'Inscrição de {enrollment.student.username} no curso {enrollment.course.title} REJEITADA.', 'info')
        
        db.session.commit()
        return redirect(url_for('manage_enrollments'))
        
    return app

# Para quick dev run
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        # CUIDADO: Este comando cria a DB se não existir.
        # Ele só funciona se database.py e models.py estiverem definidos corretamente.
        db.create_all() 
    app.run(debug=True)