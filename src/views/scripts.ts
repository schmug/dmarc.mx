export const JS = `
function toggleCard(header) {
  var card = header.parentElement;
  card.classList.toggle('expanded');
  var isExpanded = card.classList.contains('expanded');
  header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
}

/* Guard: document-level listeners persist across document.replaceChild
   (used by the loading→report transition), so only register them once. */
if (!window.__dmarcheckBound) {
  window.__dmarcheckBound = true;

  document.addEventListener('click', function(e) {
    var header = e.target.closest('.card-header');
    if (header) toggleCard(header);
  });

  document.addEventListener('keydown', function(e) {
    var header = e.target.closest('.card-header');
    if (header && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      toggleCard(header);
    }
  });

  function toggleSpfNode(node) {
    var li = node.parentElement;
    var sub = li.querySelector('ul');
    if (sub) {
      var isHidden = sub.style.display === 'none';
      sub.style.display = isHidden ? '' : 'none';
      node.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
    }
  }

  document.addEventListener('click', function(e) {
    var node = e.target.closest('.spf-node.include');
    if (node) {
      toggleSpfNode(node);
    }
  });

  document.addEventListener('keydown', function(e) {
    var node = e.target.closest('.spf-node.include');
    if (node && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      toggleSpfNode(node);
    }
  });

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.copy-btn');
    if (btn) {
      var text = btn.getAttribute('data-copy');
      navigator.clipboard.writeText(text).then(function() {
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
      });
    }
  });

  document.addEventListener('submit', function(e) {
    var form = e.target.closest('form[action="/check"]');
    if (!form) return;
    var btn = form.querySelector('button[type="submit"]');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Scanning...';
    }
    var landing = document.querySelector('.landing-main');
    if (landing) {
      var domain = form.querySelector('input[name="domain"]').value;
      var wrapper = document.createElement('div');
      wrapper.className = 'loading';
      wrapper.setAttribute('role', 'status');
      wrapper.setAttribute('aria-live', 'polite');
      var spinner = document.createElement('div');
      spinner.className = 'spinner';
      spinner.setAttribute('aria-hidden', 'true');
      var msg = document.createElement('p');
      msg.textContent = 'Scanning ' + domain + '...';
      wrapper.appendChild(spinner);
      wrapper.appendChild(msg);
      Array.from(landing.children).forEach(function(child) { child.style.display = 'none'; });
      landing.appendChild(wrapper);
    }
  });
}

(function() {
  var report = document.querySelector('.report');
  if (report) {
    var heading = report.querySelector('.domain-name');
    if (heading) {
      heading.setAttribute('tabindex', '-1');
      heading.focus();
    }
  }
  var timeEl = document.querySelector('.report-meta time[datetime]');
  if (timeEl) {
    var iso = timeEl.getAttribute('datetime');
    function updateRelative() {
      var diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
      if (diff < 5) timeEl.textContent = 'Scanned just now';
      else if (diff < 60) timeEl.textContent = 'Scanned ' + diff + 's ago';
      else if (diff < 3600) timeEl.textContent = 'Scanned ' + Math.floor(diff / 60) + 'm ago';
      else timeEl.textContent = 'Scanned ' + new Date(iso).toUTCString().replace('GMT', 'UTC');
    }
    updateRelative();
    setInterval(updateRelative, 10000);
  }

  /* Confetti celebration */
  function launchConfetti(count, colors, originEl) {
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:9999';
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    document.body.appendChild(canvas);
    var ctx = canvas.getContext('2d');
    var rect = originEl ? originEl.getBoundingClientRect() : { left: canvas.width / 2, top: canvas.height / 3 };
    var ox = rect.left + (rect.width || 0) / 2;
    var oy = rect.top + (rect.height || 0) / 2;
    var particles = [];
    for (var i = 0; i < count; i++) {
      particles.push({
        x: ox, y: oy,
        vx: (Math.random() - 0.5) * 12,
        vy: -(Math.random() * 8 + 4),
        r: Math.random() * Math.PI * 2,
        rv: (Math.random() - 0.5) * 0.2,
        w: 6 + Math.random() * 4,
        h: 4 + Math.random() * 3,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: 1
      });
    }
    var start = Date.now();
    function frame() {
      if (Date.now() - start > 4000 || particles.length === 0) {
        canvas.remove();
        return;
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (var j = particles.length - 1; j >= 0; j--) {
        var p = particles[j];
        p.vy += 0.15;
        p.x += p.vx;
        p.y += p.vy;
        p.r += p.rv;
        if (p.y > canvas.height * 0.8) p.alpha -= 0.02;
        if (p.alpha <= 0 || p.y > canvas.height) { particles.splice(j, 1); continue; }
        ctx.save();
        ctx.globalAlpha = p.alpha;
        ctx.translate(p.x, p.y);
        ctx.rotate(p.r);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
        ctx.restore();
      }
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  var sGradeInterval = null;

  function fireConfetti(grade, originEl) {
    var letter = grade.charAt(0).toUpperCase();
    var plus = grade.indexOf('+') !== -1;
    var greens = ['#22c55e', '#4ade80', '#86efac'];
    var oranges = ['#f97316', '#fb923c'];
    var golds = ['#facc15', '#fde68a'];
    var ambers = ['#f59e0b', '#fbbf24', '#d97706'];

    if (grade === 'S') {
      var sColors = ['#facc15', '#fde68a', '#f59e0b', '#d97706', '#22c55e', '#4ade80', '#f97316'];
      launchConfetti(40, sColors, originEl);
      setTimeout(function() { launchConfetti(35, sColors, originEl); }, 300);
      setTimeout(function() { launchConfetti(30, sColors, originEl); }, 600);
      sGradeInterval = setInterval(function() {
        launchConfetti(25, sColors, originEl);
        setTimeout(function() { launchConfetti(20, sColors, originEl); }, 300);
      }, 4000);
      return;
    }

    if (letter === 'A' && plus) {
      launchConfetti(35, greens.concat(oranges, golds), originEl);
      setTimeout(function() { launchConfetti(35, greens.concat(oranges, golds), originEl); }, 300);
      setTimeout(function() { launchConfetti(30, greens.concat(golds), originEl); }, 600);
    } else if (letter === 'A') {
      launchConfetti(30, greens.concat(oranges), originEl);
      setTimeout(function() { launchConfetti(30, greens.concat(oranges), originEl); }, 400);
    } else if (letter === 'B') {
      launchConfetti(30, greens, originEl);
    } else if (letter === 'C') {
      launchConfetti(12, ambers, originEl);
    }
  }

  var toggleBtn = document.querySelector('.confetti-toggle');
  if (toggleBtn) {
    var grade = toggleBtn.getAttribute('data-grade');
    var gradeEl = document.querySelector('.overall-grade');
    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var disabled = localStorage.getItem('confetti-disabled') === 'true' || reducedMotion;

    if (disabled) {
      toggleBtn.classList.add('disabled');
      toggleBtn.setAttribute('aria-pressed', 'false');
    } else {
      toggleBtn.setAttribute('aria-pressed', 'true');
      fireConfetti(grade, gradeEl);
    }

    toggleBtn.addEventListener('click', function() {
      disabled = !disabled;
      localStorage.setItem('confetti-disabled', disabled ? 'true' : 'false');
      toggleBtn.classList.toggle('disabled', disabled);
      toggleBtn.setAttribute('aria-pressed', disabled ? 'false' : 'true');
      if (disabled) {
        if (sGradeInterval) { clearInterval(sGradeInterval); sGradeInterval = null; }
      } else {
        fireConfetti(grade, gradeEl);
      }
    });
  }
})();

/* Theme toggle */
(function() {
  var toggles = document.querySelectorAll('.theme-toggle');
  if (!toggles.length) return;
  var sunIcon = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.05 3.05l1.41 1.41M11.54 11.54l1.41 1.41M3.05 12.95l1.41-1.41M11.54 4.46l1.41-1.41"/></svg>';
  var moonIcon = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M13.5 8.5a5.5 5.5 0 01-7-7 5.5 5.5 0 107 7z"/></svg>';
  var autoIcon = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="1" y="2" width="14" height="10" rx="1.5"/><path d="M5 15h6M8 12v3"/></svg>';

  function updateToggles() {
    var stored = localStorage.getItem('theme');
    toggles.forEach(function(btn) {
      if (!stored) {
        btn.innerHTML = autoIcon;
        btn.setAttribute('aria-label', 'Using system theme, switch to light');
        btn.title = 'System theme';
      } else if (stored === 'light') {
        btn.innerHTML = sunIcon;
        btn.setAttribute('aria-label', 'Light mode, switch to dark');
        btn.title = 'Light mode';
      } else {
        btn.innerHTML = moonIcon;
        btn.setAttribute('aria-label', 'Dark mode, switch to system');
        btn.title = 'Dark mode';
      }
    });
  }

  function cycle() {
    var stored = localStorage.getItem('theme');
    if (!stored) {
      localStorage.setItem('theme', 'light');
      document.documentElement.setAttribute('data-theme', 'light');
    } else if (stored === 'light') {
      localStorage.setItem('theme', 'dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      localStorage.removeItem('theme');
      document.documentElement.removeAttribute('data-theme');
    }
    updateToggles();
  }

  toggles.forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); cycle(); });
  });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateToggles);
  updateToggles();
})();

/* @ Creature easter egg */
(function() {
  if (window.__dmarcheckCreature) return;
  window.__dmarcheckCreature = true;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  var IDLE_MS = 60000;
  var COOLDOWN_MS = 120000;
  var WALK_SPEED = 120; /* pixels per second */
  var idleTimer = null;
  var creature = null;
  var eatenElements = [];
  var isActive = false;
  var useCooldown = false;

  function resetIdle() {
    clearTimeout(idleTimer);
    if (isActive) { panicAndRestore(); return; }
    idleTimer = setTimeout(spawnCreature, useCooldown ? COOLDOWN_MS : IDLE_MS);
  }

  ['mousemove', 'keydown', 'scroll', 'touchstart'].forEach(function(evt) {
    document.addEventListener(evt, resetIdle, { passive: true });
  });

  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      clearTimeout(idleTimer);
      if (isActive) { panicAndRestore(); }
    } else {
      resetIdle();
    }
  });

  resetIdle();

  function spawnCreature() {
    if (isActive || creature) return;
    isActive = true;

    creature = document.createElement('div');
    creature.className = 'at-creature';
    creature.setAttribute('tabindex', '0');
    creature.setAttribute('role', 'button');
    creature.setAttribute('aria-label', 'Stop DMarcus');

    var body = document.createElement('div');
    body.className = 'creature-body';
    body.textContent = '@';

    var eyes = document.createElement('div');
    eyes.className = 'creature-eyes';
    for (var i = 0; i < 2; i++) {
      var eye = document.createElement('div');
      eye.className = 'creature-eye';
      var pupil = document.createElement('div');
      pupil.className = 'creature-pupil';
      eye.appendChild(pupil);
      eyes.appendChild(eye);
    }
    body.appendChild(eyes);

    var legs = document.createElement('div');
    legs.className = 'creature-legs';
    for (var j = 0; j < 3; j++) {
      var leg = document.createElement('div');
      leg.className = 'creature-leg';
      legs.appendChild(leg);
    }

    creature.appendChild(body);
    creature.appendChild(legs);
    document.body.appendChild(creature);

    /* announce for screen readers */
    var announce = document.createElement('div');
    announce.setAttribute('aria-live', 'polite');
    announce.setAttribute('style', 'position:absolute;left:-9999px;');
    announce.textContent = 'DMarcus appeared!';
    document.body.appendChild(announce);
    setTimeout(function() { announce.remove(); }, 3000);

    /* start from the logo @ if present, otherwise from a random edge */
    var logoAt = document.querySelector('.logo .creature');
    var vw = window.innerWidth, vh = window.innerHeight;
    var startX, startY;

    if (logoAt) {
      var logoRect = logoAt.getBoundingClientRect();
      startX = logoRect.left;
      startY = logoRect.top;
      logoAt.style.opacity = '0';
    } else {
      var edge = Math.floor(Math.random() * 4);
      if (edge === 0) { startX = -60; startY = Math.random() * vh * 0.6 + vh * 0.1; }
      else if (edge === 1) { startX = vw + 10; startY = Math.random() * vh * 0.6 + vh * 0.1; }
      else if (edge === 2) { startX = Math.random() * vw * 0.6 + vw * 0.1; startY = -60; }
      else { startX = Math.random() * vw * 0.6 + vw * 0.1; startY = vh + 10; }
    }

    creature.style.left = startX + 'px';
    creature.style.top = startY + 'px';

    creature.addEventListener('click', function(e) { e.stopPropagation(); panicAndRestore(); });
    creature.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); panicAndRestore(); }
    });

    walkToNextTarget();
  }

  function getTargets() {
    var selectors = [
      '.logo', '.tagline', '.search-box', '.advanced-options', '.examples',
      '.api-hint', '.foss-callout', '.learn-link',
      '.report-header', '.score-snippet', '.report-meta',
      '.card', '.confetti-toggle'
    ];
    var targets = [];
    selectors.forEach(function(sel) {
      var els = document.querySelectorAll(sel);
      els.forEach(function(el) {
        if (!el.dataset.eaten && el.offsetParent !== null) targets.push(el);
      });
    });
    /* sort by vertical position */
    targets.sort(function(a, b) {
      return a.getBoundingClientRect().top - b.getBoundingClientRect().top;
    });
    return targets;
  }

  function updatePupils(targetX, targetY) {
    if (!creature) return;
    var rect = creature.getBoundingClientRect();
    var cx = rect.left + rect.width / 2;
    var cy = rect.top + rect.height / 2;
    var dx = targetX - cx, dy = targetY - cy;
    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
    var px = (dx / dist) * 2;
    var py = (dy / dist) * 2;
    var pupils = creature.querySelectorAll('.creature-pupil');
    pupils.forEach(function(p) {
      p.style.left = (3 + px) + 'px';
      p.style.top = (3 + py) + 'px';
    });
  }

  function walkTo(x, y, callback) {
    if (!creature) return;
    var rect = creature.getBoundingClientRect();
    var dx = x - rect.left, dy = y - rect.top;
    var dist = Math.sqrt(dx * dx + dy * dy);
    var duration = Math.max(0.4, dist / WALK_SPEED);

    creature.classList.add('walking');
    updatePupils(x, y);
    creature.style.transition = 'left ' + duration + 's linear, top ' + duration + 's linear';
    creature.style.left = x + 'px';
    creature.style.top = y + 'px';

    setTimeout(function() {
      if (creature) creature.classList.remove('walking');
      if (callback) callback();
    }, duration * 1000 + 50);
  }

  function walkToNextTarget() {
    if (!isActive || !creature) return;
    var targets = getTargets();
    if (targets.length === 0) {
      /* nothing left to eat — wander off */
      var vw = window.innerWidth;
      walkTo(vw + 100, creature.getBoundingClientRect().top, function() {
        cleanup();
      });
      return;
    }

    var target = targets[0];
    var tRect = target.getBoundingClientRect();
    var approachX = tRect.left - 60;
    var approachY = tRect.top + tRect.height / 2 - 30;

    walkTo(approachX, approachY, function() {
      eatElement(target);
    });
  }

  function eatElement(el) {
    if (!isActive || !creature) return;

    /* chomp animation */
    var body = creature.querySelector('.creature-body');
    if (body) body.classList.add('chomping');
    setTimeout(function() {
      if (body) body.classList.remove('chomping');
    }, 300);

    setTimeout(function() {
      if (!isActive || !creature) return;

      var rect = el.getBoundingClientRect();
      var original = {
        el: el,
        position: el.style.position,
        left: el.style.left,
        top: el.style.top,
        width: el.style.width,
        height: el.style.height,
        transition: el.style.transition,
        zIndex: el.style.zIndex,
        transform: el.style.transform,
        visibility: el.style.visibility,
        margin: el.style.margin
      };
      eatenElements.push(original);
      el.dataset.eaten = 'true';

      /* fix the element in place */
      el.style.position = 'fixed';
      el.style.left = rect.left + 'px';
      el.style.top = rect.top + 'px';
      el.style.width = rect.width + 'px';
      el.style.height = rect.height + 'px';
      el.style.margin = '0';
      el.style.zIndex = '9997';
      el.style.transition = 'left 0.6s ease-in, top 0.6s ease-in, opacity 0.6s ease-in';

      /* find nearest edge to drag toward */
      var vw = window.innerWidth, vh = window.innerHeight;
      var toLeft = rect.left, toRight = vw - rect.right;
      var toTop = rect.top, toBottom = vh - rect.bottom;
      var min = Math.min(toLeft, toRight, toTop, toBottom);
      var destX = rect.left, destY = rect.top;

      if (min === toLeft) destX = -(rect.width + 20);
      else if (min === toRight) destX = vw + 20;
      else if (min === toTop) destY = -(rect.height + 20);
      else destY = vh + 20;

      /* creature walks alongside */
      creature.classList.add('walking');
      updatePupils(destX, destY);
      creature.style.transition = 'left 0.6s ease-in, top 0.6s ease-in';
      creature.style.left = (destX + (min === toLeft ? -60 : min === toRight ? 60 : 0)) + 'px';
      creature.style.top = (destY + (min === toTop ? -60 : min === toBottom ? 60 : 0)) + 'px';

      /* drag the element */
      requestAnimationFrame(function() {
        el.style.left = destX + 'px';
        el.style.top = destY + 'px';
      });

      setTimeout(function() {
        if (!isActive) return;
        el.style.visibility = 'hidden';
        el.style.position = original.position || '';
        el.style.left = original.left || '';
        el.style.top = original.top || '';
        el.style.width = original.width || '';
        el.style.height = original.height || '';
        el.style.margin = original.margin || '';
        el.style.zIndex = original.zIndex || '';
        el.style.transition = original.transition || '';
        if (creature) creature.classList.remove('walking');

        /* walk back to visible area before next target */
        if (isActive && creature) {
          var vw2 = window.innerWidth, vh2 = window.innerHeight;
          var reenterX = Math.random() * vw2 * 0.4 + vw2 * 0.1;
          var reenterY = Math.random() * vh2 * 0.3 + vh2 * 0.1;
          walkTo(reenterX, reenterY, function() {
            walkToNextTarget();
          });
        }
      }, 700);
    }, 350);
  }

  function panicAndRestore() {
    if (!creature) { isActive = false; return; }

    /* panic animation */
    creature.classList.add('panicking', 'walking');
    var vw = window.innerWidth;
    var rect = creature.getBoundingClientRect();
    var exitX = rect.left < vw / 2 ? -80 : vw + 80;
    var midY1 = rect.top + (Math.random() > 0.5 ? -60 : 60);
    var midY2 = rect.top + (Math.random() > 0.5 ? 40 : -40);

    /* zigzag keyframes via sequential transitions */
    creature.style.transition = 'left 0.15s ease-in, top 0.15s ease-in';
    creature.style.left = (rect.left + (exitX > 0 ? 30 : -30)) + 'px';
    creature.style.top = midY1 + 'px';

    setTimeout(function() {
      if (!creature) return;
      creature.style.left = (rect.left + (exitX > 0 ? 60 : -60)) + 'px';
      creature.style.top = midY2 + 'px';
    }, 150);

    setTimeout(function() {
      if (!creature) return;
      creature.style.transition = 'left 0.2s ease-in, top 0.2s ease-in';
      creature.style.left = exitX + 'px';
      creature.style.top = midY1 + 'px';
    }, 300);

    setTimeout(function() {
      cleanup();
      restoreElements();
    }, 500);
  }

  function restoreElements() {
    eatenElements.forEach(function(item, i) {
      var el = item.el;
      setTimeout(function() {
        el.style.position = item.position || '';
        el.style.left = item.left || '';
        el.style.top = item.top || '';
        el.style.width = item.width || '';
        el.style.height = item.height || '';
        el.style.margin = item.margin || '';
        el.style.zIndex = item.zIndex || '';
        el.style.transition = item.transition || '';
        el.style.visibility = item.visibility || '';
        el.style.transform = item.transform || '';
        delete el.dataset.eaten;
      }, i * 80);
    });
    eatenElements = [];
    /* restore the logo @ */
    var logoAt = document.querySelector('.logo .creature');
    if (logoAt) logoAt.style.opacity = '';
    useCooldown = true;
    resetIdle();
  }

  function cleanup() {
    if (creature) {
      creature.remove();
      creature = null;
    }
    isActive = false;
  }
})();

/* WebMCP: expose the domain scan as a tool to in-browser agents.
   No-op in browsers without navigator.modelContext — silently does nothing. */
if (typeof navigator !== 'undefined' && navigator.modelContext && typeof navigator.modelContext.provideContext === 'function') {
  try {
    navigator.modelContext.provideContext({
      tools: [{
        name: 'scan_domain',
        description: "Run a DNS email-security scan (DMARC, SPF, DKIM, BIMI, MTA-STS, MX) on a domain and return the graded JSON result.",
        inputSchema: {
          type: 'object',
          properties: {
            domain: { type: 'string', description: 'Domain to scan, e.g. example.com' },
            selectors: { type: 'string', description: 'Optional comma-separated DKIM selectors' }
          },
          required: ['domain']
        },
        execute: async function(args) {
          var url = new URL('/api/check', location.origin);
          url.searchParams.set('domain', args.domain);
          if (args.selectors) url.searchParams.set('selectors', args.selectors);
          var r = await fetch(url.toString(), { headers: { Accept: 'application/json' } });
          if (!r.ok) throw new Error('Scan failed: ' + r.status);
          return await r.json();
        }
      }]
    });
  } catch (e) { /* ignore */ }
}

/* Pro dashboard live search/filter/sort. Looks for #domain-panel[data-pro="1"]
   and progressively enhances the toolbar form: typing in the search box,
   changing a filter, clicking a sort header, or paginating swaps the panel
   via /dashboard/domains instead of doing a full page reload. The form still
   submits as a normal GET if JS fails or is disabled, so the Apply button
   stays in the markup — we just hide it once the script boots. */
(function() {
  var initial = document.getElementById('domain-panel');
  if (!initial || initial.getAttribute('data-pro') !== '1') return;

  function getPanel() { return document.getElementById('domain-panel'); }
  function getForm() {
    var p = getPanel();
    return p ? p.querySelector('form.domain-toolbar') : null;
  }
  function hideApplyButton() {
    var form = getForm();
    if (!form) return;
    var btn = form.querySelector('.toolbar-actions button[type="submit"]');
    if (btn) btn.style.display = 'none';
  }
  hideApplyButton();

  var inflight = null;
  var searchTimer = null;

  function paramsFromForm() {
    var form = getForm();
    var p = new URLSearchParams();
    if (!form) return p;
    var fd = new FormData(form);
    fd.forEach(function(value, key) {
      var s = String(value);
      if (s !== '') p.set(key, s);
    });
    return p;
  }

  function paramsFromHref(href) {
    try { return new URL(href, location.origin).searchParams; }
    catch (e) { return new URLSearchParams(); }
  }

  function loadFragment(params) {
    if (inflight) inflight.abort();
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    inflight = ctrl;
    var qs = params.toString();
    var panelEl = getPanel();
    if (panelEl) panelEl.setAttribute('aria-busy', 'true');
    var fragmentUrl = '/dashboard/domains' + (qs ? '?' + qs : '');
    var opts = { credentials: 'same-origin', headers: { 'Accept': 'text/html' } };
    if (ctrl) opts.signal = ctrl.signal;
    fetch(fragmentUrl, opts)
      .then(function(res) {
        if (!res.ok) throw new Error('http ' + res.status);
        return res.text();
      })
      .then(function(html) {
        var current = getPanel();
        if (!current) return;
        /* DOMParser parses without executing scripts and without touching the
           live document; safer than innerHTML on a detached node. The fragment
           is same-origin authenticated HTML and domains go through esc() on
           the server, but parse-don't-execute is the right default. */
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var fresh = doc.getElementById('domain-panel');
        if (!fresh) return;
        var imported = document.importNode(fresh, true);
        /* Preserve cursor + focus on the search input across the swap so
           rapid typing doesn't flicker or strand the caret. */
        var prev = current.querySelector('input[name="q"]');
        var refocus = document.activeElement === prev;
        var selStart = prev ? prev.selectionStart : null;
        var selEnd = prev ? prev.selectionEnd : null;
        current.replaceWith(imported);
        hideApplyButton();
        if (refocus) {
          var next = imported.querySelector('input[name="q"]');
          if (next) {
            next.focus();
            try {
              if (selStart !== null && selEnd !== null) {
                next.setSelectionRange(selStart, selEnd);
              }
            } catch (e) { /* readonly inputs etc. */ }
          }
        }
        var dashUrl = '/dashboard' + (qs ? '?' + qs : '');
        history.replaceState(null, '', dashUrl);
      })
      .catch(function() { /* aborted or network error — leave panel as-is */ })
      .finally(function() {
        if (inflight === ctrl) inflight = null;
        var p = getPanel();
        if (p) p.removeAttribute('aria-busy');
      });
  }

  document.addEventListener('input', function(e) {
    if (!e.target || !e.target.matches) return;
    if (!e.target.matches('form.domain-toolbar input[name="q"]')) return;
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(function() {
      var p = paramsFromForm();
      p.delete('page');
      loadFragment(p);
    }, 250);
  });

  document.addEventListener('change', function(e) {
    if (!e.target || !e.target.matches) return;
    if (!e.target.matches('form.domain-toolbar select')) return;
    var p = paramsFromForm();
    p.delete('page');
    loadFragment(p);
  });

  document.addEventListener('submit', function(e) {
    if (!e.target || !e.target.matches || !e.target.matches('form.domain-toolbar')) return;
    e.preventDefault();
    if (searchTimer) { clearTimeout(searchTimer); searchTimer = null; }
    loadFragment(paramsFromForm());
  });

  document.addEventListener('click', function(e) {
    if (!e.target || !e.target.closest) return;
    /* Skip modified clicks so cmd/ctrl-click still opens new tabs. */
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
    var link = e.target.closest('#domain-panel a.sort-link, #domain-panel .domain-pagination a');
    if (!link) return;
    var href = link.getAttribute('href');
    if (!href || href.charAt(0) !== '/') return;
    e.preventDefault();
    loadFragment(paramsFromHref(href));
  });
})();

/* ============================================================
   Dashboard drawer + add-domain wizard (PR 3)
   Opens the drawer in-place when a row's domain link is clicked,
   hydrating from /dashboard/domain/:domain.json. Falls back to the
   existing HTML route /dashboard/domain/:domain when JS is off (the
   anchor's href still points there). Wizard is a self-contained
   3-step modal that posts to /dashboard/domain/add.
   ============================================================ */
(function() {
  var drawer = document.getElementById('domain-drawer');
  var wizard = document.getElementById('add-wizard');
  if (!drawer && !wizard) return;

  var FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  var lastFocusedBeforeOpen = null;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'style') node.setAttribute('style', attrs[k]);
        else if (k === 'text') node.textContent = attrs[k];
        else node.setAttribute(k, attrs[k]);
      }
    }
    if (children) {
      for (var i = 0; i < children.length; i++) {
        if (children[i]) node.appendChild(children[i]);
      }
    }
    return node;
  }

  function setOpen(target, open) {
    if (!target) return;
    var overlay = document.querySelector('[data-overlay-for="' + target.id + '"]');
    if (open) {
      target.hidden = false;
      if (overlay) overlay.hidden = false;
      requestAnimationFrame(function() {
        target.setAttribute('data-open', '1');
        if (overlay) overlay.setAttribute('data-open', '1');
      });
    } else {
      target.removeAttribute('data-open');
      if (overlay) overlay.removeAttribute('data-open');
      setTimeout(function() {
        target.hidden = true;
        if (overlay) overlay.hidden = true;
      }, 250);
    }
  }

  function trapFocus(scope, ev) {
    if (ev.key !== 'Tab') return;
    var nodes = Array.prototype.slice.call(scope.querySelectorAll(FOCUSABLE)).filter(function(n) {
      return !n.hidden && n.offsetParent !== null;
    });
    if (nodes.length === 0) return;
    var first = nodes[0];
    var last = nodes[nodes.length - 1];
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  }

  /* ---- Drawer ---- */
  function setDrawerStatus(text, kind) {
    var bodyEl = drawer.querySelector('[data-drawer-body]');
    if (!bodyEl) return;
    bodyEl.replaceChildren(el('div', {
      class: kind === 'error' ? 'domain-drawer-error' : 'domain-drawer-loading',
      text: text
    }));
  }

  function openDrawer(domain, triggerEl) {
    if (!drawer) return;
    lastFocusedBeforeOpen = triggerEl || document.activeElement;
    var titleEl = drawer.querySelector('.domain-drawer-title');
    if (titleEl) titleEl.textContent = domain;
    setDrawerStatus('Loading…');
    setOpen(drawer, true);
    setTimeout(function() {
      var closeBtn = drawer.querySelector('[data-drawer-close]');
      if (closeBtn) closeBtn.focus();
    }, 30);

    fetch('/dashboard/domain/' + encodeURIComponent(domain) + '.json', {
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    }).then(function(res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    }).then(function(data) {
      renderDrawerBody(data);
    }).catch(function() {
      var bodyEl = drawer.querySelector('[data-drawer-body]');
      if (!bodyEl) return;
      var fallback = el('a', {
        href: '/dashboard/domain/' + encodeURIComponent(domain),
        text: 'Open the full page instead.'
      });
      bodyEl.replaceChildren(
        el('div', { class: 'domain-drawer-error' }, [
          document.createTextNode('Couldn\\u2019t load detail. '),
          fallback
        ])
      );
    });
  }

  /* CopyButton — clipboard copy with a transient "Copied!" state. Uses
     navigator.clipboard.writeText; bails out silently on browsers without it
     (no-op rather than throwing — older browsers shouldn't break the drawer). */
  function copyButton(text, opts) {
    opts = opts || {};
    var btn = el('button', {
      type: 'button',
      class: 'drawer-copy-btn' + (opts.suggested ? ' drawer-copy-btn-suggested' : ''),
      'aria-label': opts.suggested ? 'Copy suggested fix to clipboard' : 'Copy record to clipboard'
    });
    /* Inline SVG clipboard icon — prebuilt as DOM nodes via createElementNS so
       textContent / replaceChildren stay safe. */
    function makeIcon(checked) {
      var ns = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(ns, 'svg');
      svg.setAttribute('width', '12');
      svg.setAttribute('height', '12');
      svg.setAttribute('viewBox', '0 0 16 16');
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', checked ? '2' : '1.5');
      svg.setAttribute('stroke-linecap', 'round');
      svg.setAttribute('stroke-linejoin', 'round');
      svg.setAttribute('aria-hidden', 'true');
      if (checked) {
        var p = document.createElementNS(ns, 'path');
        p.setAttribute('d', 'M3 8l3.5 3.5L13 5');
        svg.appendChild(p);
      } else {
        var rect = document.createElementNS(ns, 'rect');
        rect.setAttribute('x', '4'); rect.setAttribute('y', '3');
        rect.setAttribute('width', '8'); rect.setAttribute('height', '11');
        rect.setAttribute('rx', '1.5');
        svg.appendChild(rect);
        var lid = document.createElementNS(ns, 'path');
        lid.setAttribute('d', 'M6 3V2a1 1 0 011-1h2a1 1 0 011 1v1');
        svg.appendChild(lid);
      }
      return svg;
    }
    function paint(label, checked) {
      btn.replaceChildren(makeIcon(checked), document.createTextNode(' ' + label));
    }
    paint(opts.label || 'Copy', false);
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      if (!navigator.clipboard || !navigator.clipboard.writeText) return;
      navigator.clipboard.writeText(text).then(function() {
        btn.classList.add('drawer-copy-btn-copied');
        paint('Copied', true);
        setTimeout(function() {
          btn.classList.remove('drawer-copy-btn-copied');
          paint(opts.label || 'Copy', false);
        }, 1600);
      }, function() {});
    });
    return btn;
  }

  function gradePillEl(grade) {
    var letter = String(grade || '—').charAt(0).toUpperCase();
    var cls = 'grade-pill grade-pill-';
    if (letter === 'S') cls += 's';
    else if (letter === 'A' || letter === 'B') cls += 'a';
    else if (letter === 'C' || letter === 'D') cls += 'c';
    else cls += 'f';
    return el('span', { class: cls, text: String(grade || '—') });
  }

  function statusDotEl(status) {
    var s = (status === 'pass' || status === 'warn' || status === 'fail' || status === 'info')
      ? status : 'unknown';
    return el('span', {
      class: 'drawer-status-dot drawer-status-' + s,
      'aria-label': 'Status: ' + s,
      role: 'img'
    });
  }

  function sectionTitle(text) {
    return el('div', { class: 'drawer-section-title', text: text });
  }

  function diffCardEl(domain, diff, onMarkFixed) {
    var label = el('div', { class: 'drawer-diff-label', text: 'WHAT CHANGED TODAY' });
    var msg = el('div', { class: 'drawer-diff-msg', text: diff.change });
    /* + line: current/broken record */
    var plusText = el('span', { class: 'drawer-diff-line-text' }, [
      el('span', { class: 'drawer-diff-marker', text: '+ ' }),
      document.createTextNode(diff.current)
    ]);
    var plusRow = el('div', { class: 'drawer-diff-row drawer-diff-current' }, [
      plusText,
      copyButton(diff.current, { label: 'Current' })
    ]);
    /* − line: previous/working record (the suggested fix) */
    var minusText = el('span', { class: 'drawer-diff-line-text' }, [
      el('span', { class: 'drawer-diff-marker', text: '− ' }),
      document.createTextNode(diff.previous)
    ]);
    var minusRow = el('div', { class: 'drawer-diff-row drawer-diff-previous' }, [
      minusText,
      copyButton(diff.previous, { label: 'Copy fix', suggested: true })
    ]);
    var diffBlock = el('div', { class: 'drawer-diff-block' }, [plusRow, minusRow]);
    var fixedBtn = el('button', {
      type: 'button',
      class: 'drawer-cta-secondary drawer-cta-fixed'
    }, [document.createTextNode('✓ I fixed it (re-scan)')]);
    fixedBtn.addEventListener('click', function() {
      if (typeof onMarkFixed === 'function') onMarkFixed();
    });
    var hint = el('span', {
      class: 'drawer-diff-hint',
      text: 'Paste the green line into your DNS as a TXT record on _dmarc.' + domain
    });
    var actions = el('div', { class: 'drawer-diff-actions' }, [fixedBtn, hint]);
    return el('section', { class: 'drawer-diff-card', 'aria-label': 'What changed today' }, [
      label, msg, diffBlock, actions
    ]);
  }

  function protocolRowEl(name, info) {
    var hasRecord = !!(info && info.record);
    var statusValue = (info && info.status) || null;
    var summary = (info && info.summary) || 'no data yet';
    var dot = statusDotEl(statusValue);
    var nameEl = el('span', { class: 'drawer-protocol-name', text: name });
    var summaryEl = el('span', { class: 'drawer-protocol-summary', text: summary });
    var children = [dot, nameEl, summaryEl];
    var chevron = null;
    if (hasRecord) {
      chevron = el('span', { class: 'drawer-protocol-chevron', 'aria-hidden': 'true', text: '▸' });
      children.push(chevron);
    }
    var headBtnAttrs = {
      type: 'button',
      class: 'drawer-protocol-head',
      'aria-expanded': 'false'
    };
    if (!hasRecord) headBtnAttrs.disabled = '';
    var head = el('button', headBtnAttrs, children);
    var detail = null;
    if (hasRecord) {
      var rec = el('div', { class: 'drawer-protocol-record', text: info.record });
      detail = el('div', { class: 'drawer-protocol-detail' }, [
        rec,
        copyButton(info.record, { label: 'Copy' })
      ]);
      detail.hidden = true;
      head.addEventListener('click', function() {
        var open = !detail.hidden;
        if (open) {
          detail.hidden = true;
          head.setAttribute('aria-expanded', 'false');
          if (chevron) chevron.classList.remove('is-open');
        } else {
          detail.hidden = false;
          head.setAttribute('aria-expanded', 'true');
          if (chevron) chevron.classList.add('is-open');
        }
      });
    }
    var card = el('div', { class: 'drawer-protocol-card' }, detail ? [head, detail] : [head]);
    return card;
  }

  function recommendationRowEl(rec) {
    var pri = rec.priority === 1 ? 'p1' : rec.priority === 2 ? 'p2' : 'p3';
    var badge = el('div', {
      class: 'drawer-rec-priority drawer-rec-' + pri,
      text: 'P' + rec.priority
    });
    var title = el('div', { class: 'drawer-rec-title', text: rec.title });
    var impact = el('div', { class: 'drawer-rec-impact', text: rec.impact || rec.description || '' });
    var body = el('div', { class: 'drawer-rec-body' }, [title, impact]);
    return el('div', { class: 'drawer-rec-row' }, [badge, body]);
  }

  function historyRowEl(entry) {
    var when = entry.scannedAt
      ? new Date(entry.scannedAt * 1000).toLocaleString()
      : '—';
    /* Severity dot mirrors the grade letter, not "worst protocol". A B-grade
       scan with one failing optional protocol (e.g. BIMI not configured)
       still reads as healthy at a glance. */
    var letter = String(entry.grade || '').charAt(0).toUpperCase();
    var sev = 'pass';
    if (letter === 'F') sev = 'fail';
    else if (letter === 'C' || letter === 'D') sev = 'warn';
    var dot = statusDotEl(sev);
    var grade = el('span', { class: 'drawer-history-grade', text: String(entry.grade || '—') });
    var time = el('span', { class: 'drawer-history-time', text: when });
    return el('div', { class: 'drawer-history-row' }, [dot, grade, time]);
  }

  function setHeader(data) {
    var titleEl = drawer.querySelector('.domain-drawer-title');
    if (!titleEl) return;
    var pill = gradePillEl(data.grade);
    var name = el('span', { class: 'drawer-header-name', text: data.domain });
    var lastScan = data.lastScannedAt
      ? new Date(data.lastScannedAt * 1000).toLocaleString()
      : 'Never';
    var sub = el('span', {
      class: 'drawer-header-sub',
      text: 'Last scan ' + lastScan + ' · ' + (data.scanFrequency || '—') + ' cadence'
    });
    var stack = el('div', { class: 'drawer-header-stack' }, [name, sub]);
    titleEl.replaceChildren(pill, stack);
  }

  function renderDrawerBody(data) {
    var bodyEl = drawer.querySelector('[data-drawer-body]');
    if (!bodyEl) return;
    setHeader(data);
    var children = [];

    /* DiffCard — only when the JSON endpoint surfaced a DMARC drift. The
       "fixed it" button posts to the existing /scan handler. */
    if (data.diff) {
      children.push(diffCardEl(data.domain, data.diff, function() {
        triggerRescan(data.domain);
      }));
    }

    /* Protocols */
    var protocols = data.protocols || {};
    children.push(sectionTitle('Protocols'));
    var protoList = el('div', { class: 'drawer-protocol-list' }, [
      protocolRowEl('DMARC', protocols.dmarc),
      protocolRowEl('SPF', protocols.spf),
      protocolRowEl('DKIM', protocols.dkim),
      protocolRowEl('BIMI', protocols.bimi),
      protocolRowEl('MTA-STS', protocols.mta_sts)
    ]);
    children.push(protoList);

    /* Recommendations */
    var recs = data.recommendations || [];
    if (recs.length > 0) {
      children.push(sectionTitle('How to improve'));
      var recList = el('div', { class: 'drawer-rec-list' });
      recs.forEach(function(r) { recList.appendChild(recommendationRowEl(r)); });
      children.push(recList);
    }

    /* History */
    children.push(sectionTitle('Recent scans'));
    var hist = data.history || [];
    if (hist.length === 0) {
      var emptyContainer = el('div', { class: 'empty-state', style: 'padding: 1.5rem 0; text-align: left;' });
      var emptyText = el('p', { text: 'No scan history yet. Generate your first grade to see history and trends.', style: 'margin-bottom: 0.75rem;' });
      var scanFormEmpty = el('form', { method: 'POST', action: '/dashboard/domain/' + encodeURIComponent(data.domain) + '/scan', style: 'display: inline;' });
      var scanBtnEmpty = el('button', { type: 'submit', class: 'btn btn-secondary', text: 'Scan Now' });
      scanFormEmpty.appendChild(scanBtnEmpty);
      emptyContainer.appendChild(emptyText);
      emptyContainer.appendChild(scanFormEmpty);
      children.push(emptyContainer);
    } else {
      var histList = el('div', { class: 'drawer-history-list' });
      hist.slice(0, 8).forEach(function(h) { histList.appendChild(historyRowEl(h)); });
      children.push(histList);
    }

    bodyEl.replaceChildren.apply(bodyEl, children);

    /* Sticky footer — set/replace so a re-render doesn't stack actions. */
    var existingFooter = drawer.querySelector('.drawer-footer');
    if (existingFooter) existingFooter.remove();
    var openLink = el('a', {
      href: '/dashboard/domain/' + encodeURIComponent(data.domain),
      class: 'drawer-cta-secondary',
      text: 'Open full report →'
    });
    var rescanForm = el('form', {
      method: 'post',
      action: '/dashboard/domain/' + encodeURIComponent(data.domain) + '/scan',
      class: 'drawer-footer-form'
    }, [el('button', { type: 'submit', class: 'drawer-cta-primary', text: 'Re-scan now' })]);
    var footer = el('footer', { class: 'drawer-footer' }, [openLink, rescanForm]);
    drawer.appendChild(footer);
  }

  /* "✓ I fixed it" → POST /dashboard/domain/:domain/scan, show a toast-ish
     loading state, re-fetch the JSON. The rescan endpoint returns 303 redirect
     to /dashboard, so we deliberately use fetch with redirect:'manual' to
     avoid navigating the page out from under the drawer. */
  function triggerRescan(domain) {
    var bodyEl = drawer.querySelector('[data-drawer-body]');
    if (bodyEl) {
      bodyEl.replaceChildren(el('div', { class: 'domain-drawer-loading', text: 'Re-scanning…' }));
    }
    fetch('/dashboard/domain/' + encodeURIComponent(domain) + '/scan', {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'manual'
    }).then(function() {
      return fetch('/dashboard/domain/' + encodeURIComponent(domain) + '.json', {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      });
    }).then(function(res) {
      if (!res.ok) throw new Error('reload failed');
      return res.json();
    }).then(function(data) {
      renderDrawerBody(data);
    }).catch(function() {
      setDrawerStatus('Re-scan finished. Refresh to see updated grades.', 'error');
    });
  }

  function closeDrawer() {
    if (!drawer) return;
    setOpen(drawer, false);
    if (lastFocusedBeforeOpen && lastFocusedBeforeOpen.focus) {
      lastFocusedBeforeOpen.focus();
    }
  }

  if (drawer) {
    document.addEventListener('click', function(e) {
      var t = e.target;
      if (!t || !t.closest) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
      var link = t.closest('[data-drawer-link]');
      if (!link) return;
      var row = link.closest('[data-domain]');
      var domain = row ? row.getAttribute('data-domain') : link.textContent.trim();
      if (!domain) return;
      e.preventDefault();
      openDrawer(domain, link);
    });

    document.addEventListener('click', function(e) {
      var t = e.target;
      if (!t || !t.matches) return;
      if (t.matches('[data-drawer-close]') || t.matches('[data-overlay-for="domain-drawer"]')) {
        closeDrawer();
      }
    });

    drawer.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') closeDrawer();
      else trapFocus(drawer, e);
    });
  }

  /* ---- Wizard ---- */
  if (wizard) {
    var form = wizard.querySelector('[data-wizard-form]');
    var pill = wizard.querySelector('[data-wizard-pill]');
    var backBtn = wizard.querySelector('[data-wizard-back]');
    var nextBtn = wizard.querySelector('[data-wizard-next]');
    var submitBtn = wizard.querySelector('[data-wizard-submit]');
    var errorEl = wizard.querySelector('[data-wizard-error]');
    var domainInput = wizard.querySelector('#wizard-domain');
    var freqSelect = wizard.querySelector('#wizard-frequency');
    var confirmDom = wizard.querySelector('[data-wizard-confirm-domain]');
    var confirmFreq = wizard.querySelector('[data-wizard-confirm-frequency]');
    var step = 1;

    function showStep(n) {
      step = n;
      var steps = wizard.querySelectorAll('[data-step]');
      for (var i = 0; i < steps.length; i++) {
        var stepNum = parseInt(steps[i].getAttribute('data-step'), 10);
        if (stepNum === n) steps[i].setAttribute('data-active', '1');
        else steps[i].removeAttribute('data-active');
      }
      if (pill) pill.textContent = 'Step ' + n + ' of 3';
      if (backBtn) backBtn.hidden = n === 1;
      if (nextBtn) nextBtn.hidden = n === 3;
      if (submitBtn) submitBtn.hidden = n !== 3;
      setTimeout(function() {
        var active = wizard.querySelector('[data-step="' + n + '"]');
        if (!active) return;
        var first = active.querySelector('input, select, textarea, button');
        if (first) first.focus();
      }, 50);
    }

    function openWizard(triggerEl) {
      lastFocusedBeforeOpen = triggerEl || document.activeElement;
      if (form) form.reset();
      if (errorEl) { errorEl.hidden = true; errorEl.textContent = ''; }
      if (domainInput) domainInput.removeAttribute('aria-invalid');
      showStep(1);
      setOpen(wizard, true);
    }
    function closeWizard() {
      setOpen(wizard, false);
      if (lastFocusedBeforeOpen && lastFocusedBeforeOpen.focus) {
        lastFocusedBeforeOpen.focus();
      }
    }

    document.addEventListener('click', function(e) {
      var t = e.target;
      if (!t || !t.matches) return;
      if (t.matches('[data-wizard-open]')) {
        e.preventDefault();
        openWizard(t);
      } else if (t.matches('[data-wizard-close]') || t.matches('[data-overlay-for="add-wizard"]')) {
        closeWizard();
      } else if (t.matches('[data-wizard-back]')) {
        if (step > 1) showStep(step - 1);
      } else if (t.matches('[data-wizard-next]')) {
        if (step === 1) {
          var raw = domainInput && domainInput.value.trim().toLowerCase();
          if (!raw || !/^[a-z0-9.-]+\\.[a-z]{2,}$/.test(raw)) {
            if (errorEl) {
              errorEl.textContent = 'Enter a valid domain like example.com.';
              errorEl.hidden = false;
            }
            if (domainInput) domainInput.setAttribute('aria-invalid', 'true');
            return;
          }
          if (errorEl) errorEl.hidden = true;
          if (domainInput) domainInput.removeAttribute('aria-invalid');
          if (confirmDom) confirmDom.textContent = raw;
          showStep(2);
        } else if (step === 2) {
          var freq = freqSelect ? freqSelect.value : 'weekly';
          if (confirmFreq) confirmFreq.textContent = freq;
          showStep(3);
        }
      }
    });

    wizard.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') closeWizard();
      else trapFocus(wizard, e);
    });
  }
})();
`;
