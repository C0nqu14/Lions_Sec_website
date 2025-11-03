import os
import hashlib
import json 
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv
from database import db, bcrypt, login_manager
from flask_login import current_user, login_user, logout_user, login_required
from sqlalchemy import func, desc, asc, or_
from functools import wraps 
# Importação NECESSÁRIA para manipulação de arquivos
from werkzeug.utils import secure_filename
from datetime import datetime # Importação adicionada

# Função de hash SHA256 (mantida para a lógica CTF)
def sha256(text: str) -> str:
    """Retorna o hash SHA256 de uma string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def create_app():
    load_dotenv()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave_secreta_padrao')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- CONFIGURAÇÕES DE UPLOAD DE ARQUIVOS ---
    app.config['UPLOAD_FOLDER_USER'] = 'static/profile_pics'
    app.config['UPLOAD_FOLDER_COURSE'] = 'static/course_images'
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
    
    # Garantir que as pastas de upload existam
    if not os.path.exists(app.config['UPLOAD_FOLDER_USER']):
        os.makedirs(app.config['UPLOAD_FOLDER_USER'])
    if not os.path.exists(app.config['UPLOAD_FOLDER_COURSE']):
        os.makedirs(app.config['UPLOAD_FOLDER_COURSE'])
    # ------------------------------------------

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message_category = 'info'

    # Import de modelos após inicialização para evitar circular imports
    with app.app_context():
        from database.models import User, Course, Video, Module, Enrollment, CTF, CTFScore

    @login_manager.user_loader
    def load_user(user_id):
        from database.models import User
        return db.session.get(User, int(user_id))
    
    # --- FUNÇÕES AUXILIARES DE ARQUIVOS ---
    
    def allowed_file(filename):
        """Verifica se a extensão do arquivo é permitida."""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

    def save_profile_picture(form_picture, user_id):
        """Salva a imagem de perfil e retorna o nome do arquivo, usando o ID do usuário."""
        user_id_str = str(user_id)
        _, f_ext = os.path.splitext(form_picture.filename) 
        picture_fn = user_id_str + f_ext
        picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER_USER'], picture_fn)
        
        form_picture.save(picture_path) 
        return picture_fn
        
    def save_course_picture(form_picture, course_id):
        """Salva a imagem do curso e retorna o nome do arquivo, usando o ID do curso."""
        _, f_ext = os.path.splitext(form_picture.filename) 
        picture_fn = f'course_{course_id}{f_ext}'
        picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER_COURSE'], picture_fn)
        
        form_picture.save(picture_path) 
        return picture_fn
        
    # --------------------------------------

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
            picture_file = request.files.get('picture') 
            
            if not (username and email and password):
                flash('Preencha todos os campos obrigatórios.', 'warning')
                return redirect(url_for('register'))
                
            if User.query.filter((User.username==username)|(User.email==email)).first():
                flash('Usuário ou email já existe. Escolha outro.', 'danger')
                return redirect(url_for('register'))
                
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            image_filename = 'default.jpg' 
            
            user = User(username=username, email=email, password=hashed, user_type='aluno', image_file=image_filename)
            db.session.add(user); db.session.commit()
            
            if picture_file and picture_file.filename != '':
                if allowed_file(picture_file.filename):
                    new_filename = save_profile_picture(picture_file, user.id) 
                    user.image_file = new_filename
                    db.session.commit()
                else:
                    flash('Tipo de arquivo da foto não permitido. Usando avatar padrão.', 'warning')


            flash('Conta criada! Agora faça login para iniciar seu treinamento.', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html')


    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Você saiu da sessão.', 'info')
        return redirect(url_for('home'))

    # -------- Perfil do Usuário --------
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        from database.models import User
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            
            if 'picture' in request.files:
                picture_file = request.files['picture']
                if picture_file and allowed_file(picture_file.filename):
                    picture_filename = save_profile_picture(picture_file, current_user.id)
                    current_user.image_file = picture_filename
                elif picture_file and picture_file.filename != '':
                    flash('Tipo de arquivo não permitido para a foto de perfil.', 'warning')
                    return redirect(url_for('edit_profile'))
            
            if not username or not email:
                flash('Nome de usuário e email são obrigatórios.', 'warning')
                return redirect(url_for('edit_profile'))
            
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
        from database.models import Enrollment, CTFScore, User, Course, db 

        total_ctf_score = db.session.query(func.sum(CTFScore.score)).filter_by(user_id=current_user.id).scalar()
        total_ctf_score = int(total_ctf_score) if total_ctf_score else 0

        authorized_courses_count = Enrollment.query.filter_by(student_id=current_user.id, status='AUTORIZADO').count()
        solved_ctfs_count = CTFScore.query.filter_by(user_id=current_user.id).count()
        
        in_progress_courses = Enrollment.query.filter_by(student_id=current_user.id, status='AUTORIZADO').all()

        if current_user.user_type == 'admin':
            total_users = User.query.count()
            pending_enrollments = Enrollment.query.filter_by(status='PENDENTE').count()
            total_courses = Course.query.count()

            return render_template('dashboard_admin.html',
                                   total_users=total_users,
                                   pending_enrollments=pending_enrollments,
                                   total_courses=total_courses)
                               
        elif current_user.user_type == 'professor':
            return render_template('dashboard_professor.html')
        else: # Aluno
            return render_template('dashboard_aluno.html', 
                                   total_ctf_score=total_ctf_score,
                                   authorized_courses_count=authorized_courses_count,
                                   solved_ctfs_count=solved_ctfs_count,
                                   in_progress_courses=in_progress_courses)

    # -------- cursos (ALUNO VIEW) --------
    @app.route('/courses')
    def courses():
        from database.models import Course, Enrollment
        all_courses = Course.query.all()
        
        user_enrollments = {}
        if current_user.is_authenticated:
            enrolled = Enrollment.query.filter_by(student_id=current_user.id).all()
            enrolled_ids = {e.course_id: e.status for e in enrolled} 
            
            for course in all_courses:
                if course.professor_id == current_user.id and current_user.user_type in ['professor', 'admin']:
                    user_enrollments[course.id] = 'PROFESSOR'
                elif course.id in enrolled_ids:
                    user_enrollments[course.id] = enrolled_ids[course.id] 
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
        
        if not is_owner and (not enrollment or enrollment.status != 'AUTORIZADO'):
            flash('Sua inscrição não está AUTORIZADA. Contate o administrador.', 'warning')
            return redirect(url_for('courses'))
        
        modules = course.modules 
        current_video = None
        
        if video_id:
            video_to_watch = Video.query.get(video_id)
            if video_to_watch and video_to_watch.module and video_to_watch.module.course_id == course.id:
                current_video = video_to_watch
            else:
                 flash('Vídeo não encontrado ou não pertence a este curso.', 'danger')
        
        if not current_video and modules and modules[0].videos:
             current_video = modules[0].videos[0]
        
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
        else: # Admin vê todos os cursos
            courses = Course.query.all()
            
        return render_template('professor_courses.html', courses=courses) 

    @app.route('/course/create', methods=['GET', 'POST'])
    @professor_or_admin_required
    def create_course():
        from database.models import Course
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            difficulty = request.form.get('difficulty') 
            
            if not title or not description:
                flash('Preencha título e descrição.', 'warning')
                return render_template('create_course.html')
                
            new_course = Course(title=title, description=description, difficulty=difficulty, professor_id=current_user.id)
            db.session.add(new_course); db.session.commit()
            
            flash('Curso criado! Adicione módulos e vídeos em seguida.', 'success')
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
            
            # --- Lógica de Upload de Foto de Curso ---
            if 'course_image' in request.files:
                picture_file = request.files['course_image']
                if picture_file and allowed_file(picture_file.filename): 
                    picture_filename = save_course_picture(picture_file, course_id)
                    course.course_image = picture_filename
                elif picture_file and picture_file.filename != '':
                    flash('Tipo de arquivo não permitido para a imagem do curso.', 'warning')
                    return redirect(url_for('edit_course', course_id=course.id))
            # ----------------------------------------

            course.title = request.form.get('title')
            course.description = request.form.get('description')
            
            course.difficulty = request.form.get('difficulty') 
            
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
            db.session.delete(course); db.session.commit()
            flash('Curso deletado com sucesso!', 'success')
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

        if request.method == 'POST':
            video_title = request.form.get('video_title')
            video_url = request.form.get('video_url')
            video_description = request.form.get('video_description') 
            try:
                video_order = int(request.form.get('video_order'))
            except (ValueError, TypeError):
                video_order = 0
            
            if video_title and video_url:
                v = Video(
                    title=video_title, 
                    video_url=video_url, 
                    description=video_description, 
                    order_in_course=video_order, 
                    module_id=module.id
                )
                db.session.add(v); db.session.commit()
                flash('Vídeo adicionado!', 'success')
            else:
                 flash('Preencha título e URL do vídeo.', 'warning')
                 
            return redirect(url_for('manage_videos', module_id=module.id))
            
        videos = module.videos 

        return render_template('manage_videos.html', course=course, module=module, videos=videos)
        

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
            video.description = request.form.get('video_description') 
            try:
                video.order_in_course = int(request.form.get('video_order'))
            except (ValueError, TypeError):
                flash('Ordem deve ser um número válido.', 'warning')
                return redirect(url_for('edit_video', video_id=video.id))

            db.session.commit()
            flash('Vídeo atualizado!', 'success')
            return redirect(url_for('manage_videos', module_id=module.id))

        return render_template('edit_video.html', course=course, module=module, video=video)

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

    # --- ROTAS DE ADMIN/PROFESSOR (Gestão de CTF) ---

    @app.route('/ctfs/manage/<int:ctf_id>', methods=['GET', 'POST'])
    @professor_or_admin_required
    def manage_ctf(ctf_id):
        from database.models import CTF
        ctf = CTF.query.get_or_404(ctf_id)
        
        if request.method == 'POST':
            ctf.title = request.form.get('title')
            ctf.description = request.form.get('description')
            ctf.difficulty = request.form.get('difficulty')
            
            try:
                ctf.points = int(request.form.get('points') or 0)
            except (ValueError, TypeError):
                flash('Pontos devem ser um número válido.', 'warning')
                return redirect(url_for('manage_ctf', ctf_id=ctf.id))
                
            new_flag = request.form.get('flag')
            if new_flag:
                ctf.set_flag(new_flag)
                flash('Flag atualizada (com hash)!', 'success')

            db.session.commit()
            flash('Desafio CTF atualizado!', 'success')
            return redirect(url_for('ctfs'))

        return render_template('manage_ctf.html', ctf=ctf)
        
    @app.route('/ctfs/delete/<int:ctf_id>', methods=['POST'])
    @professor_or_admin_required
    def delete_ctf(ctf_id):
        from database.models import CTF
        ctf = CTF.query.get_or_404(ctf_id)
        
        try:
            db.session.delete(ctf); db.session.commit()
            flash(f'Desafio "{ctf.title}" deletado com sucesso.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar o CTF: {e}', 'danger')
            
        return redirect(url_for('ctfs'))
        
    # -------- CTFs (VISUALIZAÇÃO DO ALUNO) --------
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
        
        user_solved = CTFScore.query.filter_by(user_id=current_user.id, ctf_id=challenge.id).first()
        
        if request.method == 'POST':
            user_flag = request.form.get('flag', '')
            if user_solved:
                flash('Você já resolveu este desafio.', 'info')
            elif challenge.check_flag(user_flag):
                new_score = CTFScore(user_id=current_user.id, ctf_id=challenge.id, score=challenge.points)
                db.session.add(new_score); db.session.commit()
                flash(f'Flag correta! Você ganhou {challenge.points} pontos.', 'success')
            else:
                flash('Flag incorreta. Tente novamente.', 'danger')
            return redirect(url_for('ctf_challenge', ctf_id=ctf_id))
        
        is_manager = current_user.is_authenticated and current_user.user_type in ['professor', 'admin']
        
        return render_template('ctf_challenge.html', 
                               challenge=challenge, 
                               user_solved=user_solved,
                               is_manager=is_manager)


    @app.route('/ctfs/ranking')
    @login_required
    def ctf_ranking():
        from database.models import CTFScore, User, db
        
        ranking_data = db.session.query(
            User, 
            func.sum(CTFScore.score).label('total_score')
        ).join(CTFScore, User.id == CTFScore.user_id).group_by(User.id).order_by(desc('total_score')).all()
        
        ranking = []
        for user_obj, total_score in ranking_data:
            ranking.append({
                'username': user_obj.username,
                'total_score': int(total_score),
                'image_file': user_obj.image_file 
            })
        
        return render_template('ctf_ranking.html', ranking=ranking)


    # --- Rotas de ADMIN (Gestão de Utilizadores e Autorização) ---
    
    @app.route('/admin/enrollments')
    @login_required
    def manage_enrollments():
        from database.models import Enrollment, db
        
        if current_user.user_type != 'admin':
            flash('Acesso não autorizado. Você precisa ser um Administrador.', 'danger')
            return redirect(url_for('dashboard'))
            
        # CORREÇÃO DEFINITIVA: Usa 'date_posted' (agora presente em models.py)
        enrollments = Enrollment.query.order_by(
            asc(Enrollment.status != 'PENDENTE'),  
            desc(Enrollment.date_posted) 
        ).all()
        
        return render_template('admin/manage_enrollments.html', enrollments=enrollments)

    @app.route('/admin/enrollments/<int:enrollment_id>/<status>', methods=['POST'])
    @login_required
    def update_enrollment_status(enrollment_id, status):
        from database.models import Enrollment, db
        
        if current_user.user_type != 'admin':
            flash('Acesso não autorizado.', 'danger')
            return redirect(url_for('dashboard'))
            
        enrollment = Enrollment.query.get_or_404(enrollment_id)
        
        if status in ['AUTORIZADO', 'NEGADO']:
            enrollment.status = status
            db.session.commit()
            flash(f'Inscrição de {enrollment.student.username} no curso {enrollment.course.title} foi {status}.', 'success')
        else:
            flash('Status inválido.', 'danger')
            
        return redirect(url_for('manage_enrollments'))
        
    
    # ROTA: manage_users
    @app.route('/admin/users')
    @login_required
    def manage_users():
        from database.models import User
        
        if current_user.user_type != 'admin':
            flash('Acesso não autorizado. Você precisa ser um Administrador.', 'danger')
            return redirect(url_for('dashboard'))
            
        user_type = request.args.get('user_type', 'all')
        search_term = request.args.get('search', '').strip()
        
        query = User.query.filter(User.id != current_user.id)
        
        if user_type != 'all':
            query = query.filter(User.user_type == user_type)

        if search_term:
            query = query.filter(or_(
                User.username.ilike(f'%{search_term}%'),
                User.email.ilike(f'%{search_term}%')
            ))
            
        users = query.order_by(User.id.asc()).all()
        
        return render_template('admin/manage_users.html', users=users, current_search=search_term, current_filter=user_type)
        
    # ROTA: create_professor
    @app.route('/admin/professor/create', methods=['GET', 'POST'])
    @login_required
    def create_professor():
        from database.models import User
        
        if current_user.user_type != 'admin':
            flash('Acesso não autorizado. Apenas Administradores podem criar contas de Professor.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not (username and email and password):
                flash('Preencha todos os campos obrigatórios.', 'warning')
                return redirect(url_for('create_professor'))
                
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash('Usuário ou email já existe. Escolha outro.', 'danger')
                return redirect(url_for('create_professor'))
                
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            
            new_professor = User(
                username=username, 
                email=email, 
                password=hashed, 
                user_type='professor', 
                image_file='default.jpg'
            )
            db.session.add(new_professor); db.session.commit()
            
            flash(f'Conta de Professor "{username}" criada com sucesso!', 'success')
            return redirect(url_for('manage_users'))
        
        return render_template('admin/create_professor.html')

    # ROTA: delete_user
    @app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        from database.models import User
        
        if current_user.user_type != 'admin' or current_user.id == user_id:
            flash('Acesso ou operação não autorizada.', 'danger')
            return redirect(url_for('manage_users'))
            
        user_to_delete = User.query.get_or_404(user_id)
        
        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Usuário "{user_to_delete.username}" deletado com sucesso.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao deletar usuário: {e}', 'danger')

        return redirect(url_for('manage_users'))


    return app