/* scrollback — minimal markdown blog engine. No build step. */
(function () {
  const listEl = document.getElementById('post-list');
  const repoEl = document.getElementById('repo-list');
  const fileEl = document.getElementById('file-list');
  const fileContextEl = document.getElementById('file-context');
  const tabPostsEl = document.getElementById('tab-posts');
  const tabProjectsEl = document.getElementById('tab-projects');
  const panePostsEl = document.getElementById('pane-posts');
  const paneProjectsEl = document.getElementById('pane-projects');
  const contentEl = document.getElementById('content');
  const mainEl = document.querySelector('.main');
  const titleEl = document.getElementById('post-title');
  const metaEl = document.getElementById('post-meta');
  const countEl = document.getElementById('post-count');
  const searchEl = document.getElementById('search');
  const explorerEl = document.getElementById('explorer');
  const toggleEl = document.getElementById('explorer-toggle');
  const topReadoutEl = document.getElementById('top-readout');
  const topBarEl = document.getElementById('top-bar');
  const topPathEl = document.getElementById('top-path');
  const topKindEl = document.getElementById('top-kind');
  const topClockEl = document.getElementById('top-clock');
  const aboutBodyEl = document.getElementById('about-body');

  let posts = [];
  let repos = [];
  let filter = '';
  const openFolders = new Set(); // topic folders the user (or navigation) opened
  const repoCache = {}; // name -> { cfg, owner, repo, branch, desc, tree }
  const GH_API = 'https://api.github.com';

  function setTab(which) {
    const projects = which === 'projects';
    if (tabPostsEl) {
      tabPostsEl.classList.toggle('active', !projects);
      tabPostsEl.setAttribute('aria-selected', String(!projects));
    }
    if (tabProjectsEl) {
      tabProjectsEl.classList.toggle('active', projects);
      tabProjectsEl.setAttribute('aria-selected', String(projects));
    }
    if (panePostsEl) panePostsEl.hidden = projects;
    if (paneProjectsEl) paneProjectsEl.hidden = !projects;
  }

  toggleEl.addEventListener('click', () => {
    const open = explorerEl.classList.toggle('open');
    toggleEl.setAttribute('aria-expanded', String(open));
  });

  searchEl.addEventListener('input', (e) => {
    filter = e.target.value.trim().toLowerCase();
    renderList();
    renderRepos();
  });

  window.addEventListener('hashchange', route);
  // Progress tracks the content column's own scroll (page body never scrolls).
  if (mainEl) mainEl.addEventListener('scroll', scheduleProgress, { passive: true });
  else window.addEventListener('scroll', scheduleProgress, { passive: true });
  // Clicking the already-open post/project/file closes it to an empty
  // reader; clicking it once more re-opens it (same hash = no event).
  let emptyActive = false;
  document.addEventListener('click', (e) => {
    const a = e.target && e.target.closest ? e.target.closest('a[href^="#/"]') : null;
    if (!a) return;
    if (a.getAttribute('href') === location.hash) {
      e.preventDefault();
      if (emptyActive) {
        emptyActive = false;
        route();
      } else {
        showEmpty();
      }
    }
  });
  if (tabPostsEl) tabPostsEl.addEventListener('click', () => setTab('posts'));
  if (tabProjectsEl) tabProjectsEl.addEventListener('click', () => setTab('projects'));

  tickClock();
  setInterval(tickClock, 5000);

  init();

  async function init() {
    try {
      const res = await fetch('posts.json', { cache: 'no-store' });
      posts = await res.json();
      // newest first
      posts.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    } catch (err) {
      titleEl.textContent = 'Could not load posts.json';
      contentEl.innerHTML = '<p>Make sure <code>posts.json</code> exists next to <code>index.html</code>.</p>';
      console.error(err);
    }
    try {
      const res = await fetch('repos.json', { cache: 'no-store' });
      repos = await res.json();
    } catch (err) {
      // repos.json is optional — portfolio section stays hidden.
      console.warn('repos.json not loaded', err);
      repos = [];
    }
    try {
      const res = await fetch('about.md', { cache: 'no-store' });
      if (res.ok && aboutBodyEl) {
        const md = await res.text();
        aboutBodyEl.innerHTML = window.marked
          ? marked.parse(md)
          : '<p>' + escapeHtml(md) + '</p>';
        adoptAboutLinks();
      }
    } catch (err) {
      // about.md is optional — the placeholder bio stays.
      console.warn('about.md not loaded', err);
    }
    renderList();
    renderRepos();
    route();
  }

  function filteredPosts() {
    if (!filter) return posts;
    return posts.filter((p) =>
      [p.title, p.excerpt, p.slug, p.folder || '']
        .join(' ')
        .toLowerCase()
        .includes(filter)
    );
  }

  function postDir(post) {
    return 'posts/' + (post.folder ? post.folder + '/' : '');
  }

  function postPath(post) {
    // Backwards compatible: entries without `folder` resolve to posts/<file>.
    return postDir(post) + post.file;
  }

  function folderLabel(post) {
    return (post.folder || 'misc').toUpperCase();
  }

  function renderList() {
    const visible = filteredPosts();
    countEl.textContent = visible.length + ' / ' + posts.length;
    const rr = parseRoute();
    const current = rr.kind === 'post' ? rr.slug : '';
    listEl.innerHTML = '';
    if (!visible.length) {
      listEl.innerHTML = '<li style="color:var(--faint);font-size:.9rem;padding:8px 4px">No posts match.</li>';
      return;
    }
    // Group by topic folder, folders A–Z, posts newest-first within.
    const groups = {};
    for (const p of visible) {
      const f = folderLabel(p);
      (groups[f] = groups[f] || []).push(p);
    }
    for (const folder of Object.keys(groups).sort()) {
      const details = document.createElement('li');
      details.className = 'folder';
      const open = document.createElement('details');
      // Closed by default; opens when it holds the current post or the user opened it.
      if (openFolders.has(folder) || groups[folder].some((p) => p.slug === current)) {
        open.setAttribute('open', '');
      }
      open.addEventListener('toggle', () => {
        if (open.open) openFolders.add(folder);
        else openFolders.delete(folder);
      });
      const sum = document.createElement('summary');
      sum.className = 'folder-head';
      const name = document.createElement('span');
      name.textContent = folder + '/';
      const n = document.createElement('span');
      n.className = 'folder-count';
      n.textContent = groups[folder].length;
      sum.appendChild(name);
      sum.appendChild(n);
      open.appendChild(sum);
      const ul = document.createElement('ul');
      ul.className = 'folder-list';
      for (const p of groups[folder]) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = '#/' + p.slug;
        if (p.slug === current) a.classList.add('active');
        const t = document.createElement('span');
        t.className = 't';
        t.textContent = p.title;
        const m = document.createElement('span');
        m.className = 'm';
        m.textContent = p.date || '';
        a.appendChild(t);
        a.appendChild(m);
        li.appendChild(a);
        ul.appendChild(li);
      }
      open.appendChild(ul);
      details.appendChild(open);
      listEl.appendChild(details);
    }
  }

  function renderRepos() {
    if (!repoEl) return;
    repoEl.innerHTML = '';
    const visible = !filter ? repos : repos.filter((r) =>
      [r.name, r.description || '', r.url || '']
        .join(' ')
        .toLowerCase()
        .includes(filter)
    );
    if (!visible.length) {
      repoEl.innerHTML = filter
        ? '<li style="color:var(--faint);font-size:.9rem;padding:8px 4px">No repos match.</li>'
        : '<li style="color:var(--faint);font-size:.9rem;padding:8px 4px">Add repos in repos.json.</li>';
      return;
    }
    for (const r of visible) {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = '#/project/' + r.name;
      const t = document.createElement('span');
      t.className = 't';
      t.textContent = r.name;
      a.appendChild(t);
      if (r.description) {
        const m = document.createElement('span');
        m.className = 'm';
        m.textContent = r.description;
        a.appendChild(m);
      }
      li.appendChild(a);
      repoEl.appendChild(li);
    }
  }

  function parseRoute() {
    const raw = location.hash || '';
    // In-page anchors (e.g. README section links like #install) must not route.
    if (raw && !raw.startsWith('#/')) return { kind: 'anchor' };
    const h = raw.replace(/^#\/?/, '').split('?')[0];
    const segs = h.split('/').filter(Boolean);
    if (segs[0] === 'project' && segs[1]) {
      return {
        kind: 'project',
        name: decodeURIComponent(segs[1]),
        path: segs.slice(2).map(decodeURIComponent).join('/')
      };
    }
    return { kind: 'post', slug: h };
  }

  async function route() {
    explorerEl.classList.remove('open');
    toggleEl.setAttribute('aria-expanded', 'false');
    const r = parseRoute();
    if (r.kind === 'anchor') return;
    emptyActive = false;
    if (mainEl) mainEl.scrollTop = 0;
    titleEl.style.display = '';
    metaEl.style.display = '';
    if (mainEl) mainEl.classList.remove('empty');
    if (r.kind === 'project') {
      renderList();
      await loadRepoView(r.name, r.path);
      return;
    }
    if (!posts.length) return;
    if (!r.slug) {
      renderList();
      showEmpty();
      return;
    }
    renderList();
    await loadPost(r.slug);
  }

  async function loadPost(slug) {
    const post = posts.find((p) => p.slug === slug) || posts[0];
    if (!post) return;
    setTab('posts');
    titleEl.textContent = post.title;
    document.title = post.title + ' — scrollback';
    metaEl.textContent = [post.date, post.readingTime || readingTimeHint(post), post.excerpt]
      .filter(Boolean)
      .join(' · ');

    contentEl.innerHTML = '<p style="color:var(--faint)">Loading…</p>';
    try {
      const res = await fetch(postPath(post), { cache: 'no-store' });
      if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
      let md = await res.text();
      contentEl.innerHTML = renderMarkdown(md);
      enhance(post);
      updateReadout(post, md);
    } catch (err) {
      contentEl.innerHTML =
        '<p>Post file not found: <code>' +
        escapeHtml(postPath(post)) +
        '</code></p><p style="color:var(--muted)">Check <code>folder</code> and <code>file</code> in <code>posts.json</code>.</p>';
      console.error(err);
      updateReadout(post, '');
    }
    // highlight active link
    listEl.querySelectorAll('a').forEach((a) => {
      a.classList.toggle('active', a.getAttribute('href') === '#/' + post.slug);
    });
    if (repoEl) repoEl.querySelectorAll('a').forEach((a) => a.classList.remove('active'));
  }

  /* ---- GitHub repo explorer ---- */

  async function gh(path) {
    const res = await fetch(GH_API + path, { headers: { Accept: 'application/vnd.github+json' } });
    if (res.status === 403 && res.headers.get('X-RateLimit-Remaining') === '0') {
      const e = new Error('GitHub API rate limit reached');
      e.rateLimited = true;
      throw e;
    }
    if (res.status === 404) {
      const e = new Error('not found on GitHub');
      e.notFound = true;
      throw e;
    }
    if (!res.ok) throw new Error('GitHub API ' + res.status);
    return res.json();
  }

  async function loadRepoCfg(name) {
    if (repoCache[name]) return repoCache[name];
    const cfg = repos.find((r) => r.name === name);
    if (!cfg || !cfg.repo) {
      const e = new Error('repo not listed in repos.json');
      e.notFound = true;
      throw e;
    }
    const parts = cfg.repo.split('/');
    const entry = {
      cfg: cfg,
      owner: parts[0],
      repo: parts[1],
      branch: cfg.branch || null,
      desc: cfg.description || '',
      tree: null
    };
    repoCache[name] = entry;
    if (!entry.branch) {
      const meta = await gh('/repos/' + entry.owner + '/' + entry.repo);
      entry.branch = meta.default_branch || 'main';
      if (!entry.desc && meta.description) entry.desc = meta.description;
    }
    const t = await gh('/repos/' + entry.owner + '/' + entry.repo + '/git/trees/' + entry.branch + '?recursive=1');
    entry.tree = (t.tree || [])
      .filter((e) => e.type === 'blob' && !e.path.startsWith('.git/'))
      .map((e) => e.path)
      .sort();
    return entry;
  }

  function rawBase(entry, dir) {
    return 'https://raw.githubusercontent.com/' + entry.owner + '/' + entry.repo +
      '/' + entry.branch + '/' + (dir ? dir + '/' : '');
  }

  function blobUrl(entry, path) {
    return 'https://github.com/' + entry.owner + '/' + entry.repo +
      '/blob/' + entry.branch + '/' + path;
  }

  function absoluteUrl(base, rel) {
    try { return new URL(rel, base).href; } catch (e) { return rel; }
  }

  function findReadme(tree) {
    return tree.find((p) => /(^|\/)readme(\.[a-z0-9]+)?$/i.test(p)) || tree[0] || '';
  }

  async function loadRepoView(name, subpath) {
    setTab('projects');
    const cfg = repos.find((r) => r.name === name);
    if (listEl) listEl.querySelectorAll('a').forEach((a) => a.classList.remove('active'));
    if (repoEl) repoEl.querySelectorAll('a').forEach((a) => {
      a.classList.toggle('active', a.getAttribute('href') === '#/project/' + name);
    });
    titleEl.textContent = name;
    contentEl.innerHTML = '<p style="color:var(--faint)">Fetching repo…</p>';
    try {
      const entry = await loadRepoCfg(name);
      if (!subpath) subpath = findReadme(entry.tree);
      renderFileTree(entry, subpath);
      await loadRepoFile(entry, subpath);
    } catch (err) {
      if (fileContextEl) fileContextEl.textContent = (cfg && cfg.repo) || name;
      const msg = err.rateLimited
        ? 'GitHub API rate limit reached — try again in an hour.'
        : 'Could not load this repo from GitHub (' + err.message + ').';
      contentEl.innerHTML = '<p>' + escapeHtml(msg) + '</p>' +
        (cfg && cfg.url
          ? '<p><a href="' + escapeHtml(cfg.url) + '" target="_blank" rel="noopener">View on GitHub ↗</a></p>'
          : '');
      titleEl.textContent = name;
      metaEl.textContent = '';
      setTopKind('Current Project');
      setTopPath('> ' + name.toUpperCase());
      updateStats(0);
      console.warn(err);
    }
  }

  function renderFileTree(entry, activePath) {
    if (fileContextEl) {
      fileContextEl.innerHTML = '';
      const ctx = document.createElement('span');
      ctx.textContent = entry.cfg.repo + '@' + entry.branch;
      fileContextEl.appendChild(ctx);
      if (entry.cfg.url) {
        const out = document.createElement('a');
        out.href = entry.cfg.url;
        out.target = '_blank';
        out.rel = 'noopener';
        out.textContent = 'GitHub ↗';
        fileContextEl.appendChild(out);
      }
    }
    if (!fileEl) return;
    fileEl.innerHTML = '';
    const root = { dirs: {}, files: [] };
    const paths = entry.tree.length > 1500 ? entry.tree.slice(0, 1500) : entry.tree;
    for (const p of paths) {
      const parts = p.split('/');
      let node = root;
      for (let i = 0; i < parts.length - 1; i++) {
        node.dirs[parts[i]] = node.dirs[parts[i]] || { dirs: {}, files: [] };
        node = node.dirs[parts[i]];
      }
      node.files.push(parts[parts.length - 1]);
    }
    buildTreeLevel(entry, root, '', activePath, fileEl);
    if (entry.tree.length > 1500) {
      const li = document.createElement('li');
      li.style.cssText = 'color:var(--faint);font-size:.8rem;padding:8px 4px';
      li.textContent = '… +' + (entry.tree.length - 1500) + ' more files (truncated)';
      fileEl.appendChild(li);
    }
  }

  function buildTreeLevel(entry, node, prefix, activePath, ul) {
    for (const d of Object.keys(node.dirs).sort()) {
      const full = prefix + d;
      const li = document.createElement('li');
      li.className = 'folder';
      const det = document.createElement('details');
      if (activePath === full || activePath.indexOf(full + '/') === 0) det.setAttribute('open', '');
      const sum = document.createElement('summary');
      sum.className = 'folder-head';
      const nm = document.createElement('span');
      nm.textContent = d + '/';
      sum.appendChild(nm);
      det.appendChild(sum);
      const sub = document.createElement('ul');
      sub.className = 'folder-list';
      buildTreeLevel(entry, node.dirs[d], full + '/', activePath, sub);
      det.appendChild(sub);
      li.appendChild(det);
      ul.appendChild(li);
    }
    for (const f of node.files.sort()) {
      const full = prefix + f;
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = '#/project/' + entry.cfg.name + '/' +
        full.split('/').map(encodeURIComponent).join('/');
      if (full === activePath) a.classList.add('active');
      const t = document.createElement('span');
      t.className = 't';
      t.textContent = f;
      a.appendChild(t);
      li.appendChild(a);
      ul.appendChild(li);
    }
  }

  function isImageExt(ext) {
    return ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico'].indexOf(ext) !== -1;
  }

  function isMarkdownExt(ext) {
    return ['md', 'markdown', 'mdown', 'mkd'].indexOf(ext) !== -1;
  }

  function codeLang(path) {
    const base = path.split('/').pop().toLowerCase();
    const named = {
      'dockerfile': 'dockerfile', 'makefile': 'makefile', 'cmakelists.txt': 'cmake'
    };
    if (named[base]) return named[base];
    const ext = base.indexOf('.') !== -1 ? base.split('.').pop() : '';
    const map = {
      js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
      ts: 'typescript', tsx: 'typescript', py: 'python', rb: 'ruby',
      java: 'java', c: 'c', h: 'c', cpp: 'cpp', hpp: 'cpp', cc: 'cpp',
      cs: 'csharp', go: 'go', rs: 'rust', php: 'php', swift: 'swift',
      kt: 'kotlin', scala: 'scala', sh: 'bash', bash: 'bash', zsh: 'bash',
      yml: 'yaml', yaml: 'yaml', json: 'json', xml: 'xml', html: 'xml',
      htm: 'xml', vue: 'xml', svelte: 'xml', css: 'css', scss: 'css',
      sql: 'sql', toml: 'ini', ini: 'ini', cfg: 'ini', lua: 'lua',
      r: 'r', pl: 'perl', ex: 'elixir', exs: 'elixir', clj: 'clojure',
      hs: 'haskell', ml: 'ocaml', vim: 'vim', ps1: 'powershell',
      bat: 'dos', cmd: 'dos', diff: 'diff', patch: 'diff', tex: 'latex',
      mk: 'makefile', cmake: 'cmake', graphql: 'graphql', gql: 'graphql'
    };
    if (map[ext]) return map[ext];
    try {
      if (window.hljs && window.hljs.getLanguage && window.hljs.getLanguage(ext)) return ext;
    } catch (e) { /* ignore */ }
    return '';
  }

  async function loadRepoFile(entry, path) {
    if (!path) {
      contentEl.innerHTML = '<p style="color:var(--faint)">This repo has no browsable files.</p>';
      return;
    }
    contentEl.innerHTML = '<p style="color:var(--faint)">Loading ' + escapeHtml(path) + '…</p>';
    const fname = path.split('/').pop();
    titleEl.textContent = fname;
    document.title = entry.cfg.name + '/' + path + ' — scrollback';
    metaEl.textContent = [entry.cfg.repo, entry.branch, entry.desc].filter(Boolean).join(' · ');
    setTopKind('Current File');
    setTopPath('> ' + path.split('/').pop().toUpperCase());
    const url = rawBase(entry, '') + path.split('/').map(encodeURIComponent).join('/');
    let res;
    try {
      res = await fetch(url);
    } catch (e) {
      throw new Error('network error');
    }
    if (res.status === 404) {
      const e = new Error('file not found in branch ' + entry.branch);
      e.notFound = true;
      throw e;
    }
    if (!res.ok) throw new Error('raw fetch ' + res.status);
    const ext = fname.indexOf('.') !== -1 ? fname.split('.').pop().toLowerCase() : '';
    if (ext === 'svg') {
      // raw.githubusercontent serves SVG as text/plain+nosniff: browsers refuse <img>.
      contentEl.innerHTML = '<p>SVG preview is blocked by GitHub raw MIME policy.</p>' +
        '<p><a href="' + escapeHtml(blobUrl(entry, path)) + '" target="_blank" rel="noopener">View on GitHub ↗</a></p>';
      updateStats(0);
      return;
    }
    if (isImageExt(ext)) {
      contentEl.innerHTML = '';
      const img = document.createElement('img');
      img.src = url;
      img.alt = path;
      img.loading = 'lazy';
      contentEl.appendChild(img);
      updateStats(0);
      return;
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > 400 * 1024) return repoTooBig(entry, path, buf.byteLength, false);
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < Math.min(bytes.length, 8000); i++) {
      if (bytes[i] === 0) return repoTooBig(entry, path, buf.byteLength, true);
    }
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
    if (isMarkdownExt(ext) || (!ext && /(^|\/)readme$/i.test(path))) {
      contentEl.innerHTML = renderMarkdown(text);
      resolveRepoLinks(entry, path);
      enhanceCode();
    } else {
      const lang = codeLang(path);
      contentEl.innerHTML = '<pre><code' + (lang ? ' class="language-' + lang + '"' : '') + '>' +
        escapeHtml(text) + '</code></pre>';
      enhanceCode();
    }
    updateStats(countWords(text));
  }

  function repoTooBig(entry, path, size, binary) {
    contentEl.innerHTML = '<p>' + (binary ? 'Binary file' : 'File too large to preview') +
      ' (' + Math.round(size / 1024) + ' KB).</p>' +
      '<p><a href="' + escapeHtml(blobUrl(entry, path)) + '" target="_blank" rel="noopener">View on GitHub ↗</a></p>';
    updateStats(0);
  }

  function resolveRepoLinks(entry, path) {
    const dir = path.indexOf('/') !== -1 ? path.slice(0, path.lastIndexOf('/') + 1) : '';
    const rawDir = rawBase(entry, dir.replace(/\/$/, ''));
    const blobDir = 'https://github.com/' + entry.owner + '/' + entry.repo +
      '/blob/' + entry.branch + '/' + dir;
    contentEl.querySelectorAll('img').forEach((img) => {
      const src = img.getAttribute('src') || '';
      if (!src || /^(https?:|data:|blob:|#)/i.test(src) || src.startsWith('/')) return;
      img.setAttribute('src', absoluteUrl(rawDir, src));
      img.setAttribute('loading', 'lazy');
    });
    contentEl.querySelectorAll('a').forEach((a) => {
      const href = a.getAttribute('href') || '';
      if (!href || /^(https?:|mailto:|#)/i.test(href) || href.startsWith('#/')) return;
      a.setAttribute('href', absoluteUrl(blobDir, href));
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener');
    });
  }

  function readingTimeHint(post) {
    return post.words ? Math.max(1, Math.round(post.words / 200)) + ' min read' : '';
  }

  function renderMarkdown(md) {
    if (window.marked) {
      marked.setOptions({ gfm: true, breaks: false });
      return marked.parse(md);
    }
    // Tiny fallback if CDN blocked: headers, bold, code, links only.
    return '<pre>' + escapeHtml(md) + '</pre>';
  }

  function enhance(post) {
    enhanceImages(post);
    enhanceCode();
  }

  function enhanceImages(post) {
    // Resolve image paths against the post's own folder:
    // - `images/...`            → kept as-is (root-relative, recommended)
    // - `../images/...`         → legacy flat layout, rewritten to `images/...`
    // - `./pic.png` / `pic.png` → resolved inside `posts/<folder>/`
    // - absolute URLs           → untouched
    const dir = post ? postDir(post) : 'posts/';
    contentEl.querySelectorAll('img').forEach((img) => {
      let src = img.getAttribute('src') || '';
      if (/^(https?:|data:|blob:|#)/i.test(src) || src.startsWith('/')) { /* external — keep */ }
      else if (src.startsWith('../images/')) src = src.slice(3);
      else if (src.startsWith('./')) src = dir + src.slice(2);
      else if (src.startsWith('images/')) { /* already root-relative, keep */ }
      else if (!src.startsWith('../')) src = dir + src;
      img.setAttribute('src', src);
      img.setAttribute('loading', 'lazy');
    });
  }

  function enhanceCode() {
    // Wrap tables for horizontal scroll on mobile.
    contentEl.querySelectorAll('table').forEach((tbl) => {
      const wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      tbl.parentNode.insertBefore(wrap, tbl);
      wrap.appendChild(tbl);
    });
    // Add lang label + copy button to code blocks + syntax highlighting.
    contentEl.querySelectorAll('pre').forEach((pre) => {
      const code = pre.querySelector('code');
      let lang = 'code';
      if (code) {
        const m = (code.className || '').match(/language-(\S+)/);
        if (m) lang = m[1];
      }
      const head = document.createElement('div');
      head.className = 'code-head';
      const label = document.createElement('span');
      label.textContent = '[' + lang.toUpperCase() + ']';
      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.textContent = '[COPY]';
      btn.addEventListener('click', async () => {
        const ok = await copyText(pre.dataset.raw || (code ? code.innerText : pre.innerText));
        btn.textContent = ok ? '[COPIED]' : 'select + ⌘C';
        if (ok) setTimeout(() => (btn.textContent = '[COPY]'), 1500);
      });
      head.appendChild(label);
      head.appendChild(btn);
      // Frame the block: header sits OUTSIDE the scroller so it can
      // never be left behind on horizontal scroll (no sticky needed).
      const wrap = document.createElement('div');
      wrap.className = 'codewrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(head);
      wrap.appendChild(pre);
    });
    // Run syntax highlighting now + retry if hljs script hasn't arrived yet.
    highlightAllWithRetry(25);
    // Line numbers immediately (idempotent) — never wait on highlighting.
    numberLines();
  }

  // Line numbers ride inline in each row: no overlay strip, so nothing
  // can cover code or misalign — and [COPY] reads from dataset.raw.
  function numberLines() {
    contentEl.querySelectorAll('pre').forEach((pre) => {
      if (pre.dataset.ln) return;
      const code = pre.querySelector('code');
      if (!code) return;
      const raw = code.textContent || '';
      pre.dataset.raw = raw;
      const cls = (code.className || '').match(/language-(\S+)/);
      const lang = cls ? cls[1] : '';
      const canHl = !!(lang && window.hljs && window.hljs.getLanguage &&
        window.hljs.highlight && window.hljs.getLanguage(lang));
      const lines = raw.split('\n');
      if (lines.length && lines[lines.length - 1] === '') lines.pop();
      const rows = lines.map((t, i) => {
        let html;
        if (canHl) {
          try { html = window.hljs.highlight(t, { language: lang }).value; }
          catch (e) { html = escapeHtml(t); }
        } else {
          html = escapeHtml(t);
        }
        return '<span class="code-line"><span class="ln">' + (i + 1) + '</span>' + html + '</span>';
      });
      code.innerHTML = rows.join('');
      pre.dataset.ln = '1';
    });
  }

  function highlightAllWithRetry(left) {
    if (window.hljs) {
      try {
        contentEl.querySelectorAll('pre code').forEach((code) => {
          // Numbered blocks are already highlighted per-line; never touch them.
          const pre = code.closest ? code.closest('pre') : null;
          if (code.dataset.highlighted || (pre && pre.dataset.ln)) return;
          window.hljs.highlightElement(code);
        });
      } catch (e) {
        console.warn('highlight failed', e);
      }
      return;
    }
    if (left <= 0) {
      console.warn('hljs not loaded — code blocks unhighlighted. Check CDN.');
      return;
    }
    setTimeout(() => highlightAllWithRetry(left - 1), 200);
  }

  function updateReadout(post, md) {
    const words = post.words || countWords(md || contentEl.innerText || '');
    setTopKind('Current post');
    setTopPath('> ' + String(post.file || '---').toUpperCase());
    updateStats(words);
  }

  function setTopPath(text) {
    if (topPathEl) topPathEl.textContent = text;
  }

  function setTopKind(text) {
    if (topKindEl) topKindEl.textContent = text;
  }

  function showEmpty() {
    const r = parseRoute();
    const proj = r.kind === 'project';
    emptyActive = true;
    titleEl.style.display = 'none';
    metaEl.style.display = 'none';
    contentEl.innerHTML = '';
    document.title = 'scrollback';
    if (mainEl) mainEl.classList.add('empty');
    setTopKind(proj ? 'Current Project' : 'Current Post');
    setTopPath('> NONE');
    if (topReadoutEl) topReadoutEl.textContent = '> ---W │ --MIN <';
    updateProgress();
    document.querySelectorAll('#explorer a.active').forEach((x) => x.classList.remove('active'));
  }

  function updateStats(words) {
    const mins = Math.max(1, Math.round(words / 200));
    const base = '> ' + words + 'W │ ' + mins + 'MIN <';
    if (topReadoutEl) topReadoutEl.textContent = base;
    updateProgress();
  }

  function countWords(s) {
    const w = String(s).trim().split(/\s+/).filter(Boolean);
    return w.length;
  }

  // A lone [GitHub](url) paragraph in about.md becomes the sidebar
  // GITHUB box destination (and is consumed so it isn't duplicated).
  function adoptAboutLinks() {
    if (!aboutBodyEl) return;
    const btn = document.querySelector('a.foot-link');
    if (!btn) return;
    const links = aboutBodyEl.querySelectorAll('a');
    for (const a of links) {
      if (/^\s*github\s*$/i.test(a.textContent || '')) {
        if (a.href) btn.href = a.href;
        const p = a.closest('p');
        if (p && p.textContent.trim().toLowerCase() === 'github') p.remove();
        else a.replaceWith(document.createTextNode(a.textContent));
        return;
      }
    }
  }

  function tickClock() {    if (!topClockEl) return;
    const d = new Date();
    topClockEl.textContent =
      String(d.getHours()).padStart(2, '0') +
      ':' + String(d.getMinutes()).padStart(2, '0');
  }

  let progressQueued = false;
  function scheduleProgress() {
    if (progressQueued) return;
    progressQueued = true;
    requestAnimationFrame(() => {
      progressQueued = false;
      updateProgress();
    });
  }

  // Bar cells are <i> boxes built once, then toggled. Never use
  // shade characters here: they routinely fall back to a
  // different font with mismatched vertical metrics.
  let barCells = null;
  function updateProgress() {
    const scroller = mainEl || document.documentElement;
    const max = scroller.scrollHeight - scroller.clientHeight;
    const pos = scroller === mainEl ? scroller.scrollTop : window.scrollY;
    const ratio = max > 0 ? Math.min(1, Math.max(0, pos / max)) : 0;
    const filled = Math.round(ratio * 10);
    if (topBarEl) {
      if (!barCells) {
        topBarEl.textContent = '';
        barCells = [];
        for (let i = 0; i < 10; i++) {
          const c = document.createElement('i');
          topBarEl.appendChild(c);
          barCells.push(c);
        }
      }
      barCells.forEach((c, i) => c.classList.toggle('on', i < filled));
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  // navigator.clipboard needs a secure context and permissions; fall back
  // to a hidden textarea + execCommand so copy works over plain http too.
  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      throw new Error('no async clipboard');
    } catch (e) {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '0';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        return !!ok;
      } catch (e2) {
        return false;
      }
    }
  }
})();
