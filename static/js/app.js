// Mascote: piscar olhos e toggle
(function(){
    function blink(){
      const l = document.getElementById('eyeL');
      const r = document.getElementById('eyeR');
      if(!l || !r) return;
      const oldL = l.getAttribute('r') || '5';
      const oldR = r.getAttribute('r') || '5';
      l.setAttribute('r','1'); r.setAttribute('r','1');
      setTimeout(()=>{ l.setAttribute('r', oldL); r.setAttribute('r', oldR); }, 120);
    }
    setInterval(blink, 2500 + Math.random()*1500);
  
    document.getElementById('toggle-mascot')?.addEventListener('click', ()=>{
      const el = document.getElementById('mascot');
      if(!el) return;
      el.classList.toggle('hidden');
    });
  
    // Auto-hide flashes
    setTimeout(()=>{
      document.querySelectorAll('.flash').forEach(el=>{
        el.style.transition='opacity .4s ease';
        el.style.opacity='0';
        setTimeout(()=>el.remove(), 400);
      });
    }, 4200);
  })();
  