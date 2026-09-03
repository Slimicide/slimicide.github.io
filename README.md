# scrollback — minimal markdown blog

Dark, single-page, no-build blog for GitHub Pages. ~50 KB + `marked`/`highlight.js` CDN.

## Structure

```
index.html                  layout + explorer sidebar
style.css                   DOS/ANSI theme (tweak :root vars)
app.js                      loads posts.json → renders markdown
posts.json                  index of posts (slug, folder, file, date)
repos.json                  portfolio repos for the PROJECTS section
                            ({name, repo: "owner/name", branch?, url, description})
posts/<topic>/<slug>.md     your posts, grouped by topic folder
images/<topic>/<slug>/      per-post images (mirrors posts/)
.nojekyll                   serve as-is on Pages
```

The explorer groups posts under their `folder` heading (`META/`, `DEMO/`, …).
Entries without `folder` fall back to `posts/<file>` and group under `MISC/`.

## Add a post (30s)

1. Pick a topic folder (or make one): `posts/notes/my-slug.md`
2. Optional images: `images/notes/my-slug/cover.png`, referenced as `images/notes/my-slug/cover.png` — or colocate next to the post and use `./cover.png`
3. Add entry to `posts.json` with matching `folder`
4. Push to `main`

## Showcase a repo (30s)

1. Add to `repos.json`: `{ "name": "my-app", "repo": "you/my-app", "url": "https://github.com/you/my-app", "description": "..." }`
   (`branch` optional — defaults to the repo's default branch.)
2. Clicking it opens the repo in-page: README renders in the post
   renderer, the PROJECTS tab shows the full file tree below the repo
   list, any text file renders
   (markdown / code with highlighting, line numbers and copy buttons /
   images). Binary and >400 KB files link out to GitHub instead.
   Unauthenticated GitHub API allows ~60 loads/hour/IP.

## Deploy to GitHub Pages

1. Push this folder as repo root
2. GitHub → Settings → Pages → Deploy from branch → `main` / `/ (root)`
3. Open `https://<user>.github.io/<repo>/#/your-slug`

Local preview: `python3 -m http.server 8000` then open `http://localhost:8000`

## Customise

- Colours: `:root` vars in `style.css`
- GitHub link: `href` on `.foot-link` in `index.html`
