# AI understanding — interactive guide

Static, offline-friendly HTML explaining **tokens**, **vectors / embeddings**, **how embeddings are learned**, **transformers**, **autoregressive generation**, **agents**, and **token efficiency**. Includes SVG animations and small interactive demos (temperature / top-p, cosine similarity, toy “training” clustering).

## Read it on the web

After you enable GitHub Pages on this repository:

1. Repo **Settings** → **Pages**
2. **Build and deployment**: Source **Deploy from a branch**
3. Branch **main** → folder **/ (root)** → Save

Your site URL will be:

**https://darshangr.github.io/AI-understanding/**

(`index.html` is served automatically at the repo root.)

You can also open `index.html` directly on GitHub via **Code** → click `index.html` → **Raw** is less readable; prefer the Pages URL above.

## Science fair project guide

`science-fair/frame-rate-project.html` is a printable, 13-page guide for a kids' science fair project: *How fast do drawings need to move to become a movie?* (frame rate, persistence of vision, and the phi phenomenon). It covers the background science, a zoetrope build, a digital flipbook, the procedure, a data sheet, graphs, a display board plan, and parent notes. The web version also includes an FPS tester with a hidden-speed "mystery mode" for running volunteers.

- Web: **https://darshangr.github.io/AI-understanding/science-fair/frame-rate-project.html**
- PDF (for printing or emailing): `science-fair/frame-rate-project.pdf`

To regenerate the PDF after editing the HTML:

```bash
google-chrome --headless=new --no-pdf-header-footer --virtual-time-budget=2000 \
  --print-to-pdf=science-fair/frame-rate-project.pdf science-fair/frame-rate-project.html
```

## Local preview

```bash
open index.html
```

## Source

Same content as `public/ai-concepts-guide.html` in the author’s local **localaura** project (published here as `index.html` for GitHub Pages).

---

MIT License — share freely.
