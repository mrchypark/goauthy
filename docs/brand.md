# GoAuthy brand

Approved direction: B / Gateway (2026-09-26). Two separated planes form an open gateway. Use the mark left of the wordmark; use the mark alone for the favicon.

- Product name and wordmark: **GoAuthy**. Keep `goauthy` for code, package names and URLs.
- Wordmark: Manrope 600, letter spacing -0.04em.
- Interface: Manrope for Latin and numbers, Pretendard for Korean; body 400, controls 500–600, headings 600.
- Mark: forest #173F35 and orange #F36B3F. On dark surfaces the forest plane becomes light. Authentication pages inherit the client theme's high-contrast foreground for that plane.
- Fonts are bundled and served from the same origin. No external font requests. `font-display: swap` preserves usable text while loading.

Assets live in `internal/branding/assets`. Manrope is from google/fonts (OFL); Pretendard is v1.3.9 from orioncactus/pretendard (OFL). Both licenses are bundled alongside the fonts. The generated concept was redrawn as simple geometry for interface use; the favicon is SVG. Explicitly configured deployment favicons retain precedence.
