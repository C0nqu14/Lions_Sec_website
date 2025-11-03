document.addEventListener('DOMContentLoaded', () => {
    // ----------------------------------------------------------------------
    // [1] THREE.JS (Data Stream Vermelho) - Fundo Animado
    // ----------------------------------------------------------------------
    const RED_COLOR = 0xcc0000; 

    const canvas = document.getElementById('three-canvas');
    if (canvas && typeof THREE !== 'undefined') {
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true }); 
        
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        renderer.setClearColor(0x000000, 0); 
        camera.position.z = 250;

        const particleCount = 10000;
        const geometry = new THREE.BufferGeometry();
        const positions = [];
        for (let i = 0; i < particleCount; i++) {
            positions.push((Math.random() - 0.5) * 1000);
            positions.push((Math.random() - 0.5) * 1000);
            positions.push((Math.random() - 0.5) * 1000);
        }
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));

        const material = new THREE.PointsMaterial({
            color: RED_COLOR,
            size: 1.5,
            blending: THREE.AdditiveBlending, 
            transparent: true,
            opacity: 0.8
        });

        const particles = new THREE.Points(geometry, material);
        scene.add(particles);

        const mouse = { x: 0, y: 0 };
        document.addEventListener('mousemove', (event) => {
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
        });

        function animate(time) {
            requestAnimationFrame(animate);
            particles.rotation.y = time * 0.00005; 
            particles.rotation.x = time * 0.00002; 
            camera.position.x += (mouse.x * 20 - camera.position.x) * 0.03;
            camera.position.y += (-mouse.y * 20 - camera.position.y) * 0.03;
            camera.lookAt(scene.position); 
            renderer.render(scene, camera);
        }

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        animate();
    }
    
    // ----------------------------------------------------------------------
    // [2] EFEITO SCRAMBLED/CRIPTOGRAFIA (Requerendo JS)
    // ----------------------------------------------------------------------
    
    const chars = '!<>-_\\/[]{}—=+*^#?&$@';
    
    function scrambleText(element) {
        const originalText = element.dataset.originalText;
        let iteration = 0;
        const speed = 30; // ms por iteração

        const interval = setInterval(() => {
            element.textContent = originalText
                .split('')
                .map((char, index) => {
                    if (index < iteration) {
                        return char;
                    }
                    return chars[Math.floor(Math.random() * chars.length)];
                })
                .join('');

            if (iteration >= originalText.length) {
                clearInterval(interval);
            }
            iteration += 1 / 3; // Ajusta a velocidade de revelação
        }, speed);
    }
    
    // [3] Ajuste de Links de Navegação para o Efeito Scramble
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    // Inicialização (prepara os links para o scramble)
    navLinks.forEach(link => {
        link.classList.add('scramble-target');
        // Usamos o textContent como originalText e o armazenamos no dataset
        link.dataset.originalText = link.textContent;
        
        link.addEventListener('mouseenter', () => {
             // Só inicia o scramble se o texto já não estiver a meio de uma animação
             if (link.textContent === link.dataset.originalText) {
                scrambleText(link);
            }
        });
    });

});