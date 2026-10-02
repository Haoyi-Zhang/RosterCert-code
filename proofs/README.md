# Standalone article source

`analysis.tex` is a recursively inlined, self-contained copy of the current article. It contains no `\input`, BibTeX invocation, project-directory dependency, repository URL, or network dependency. Its bibliography is embedded from the final generated `main.bbl`.

`analysis.pdf` is 36 pages and contains the same article text and 80 cited references as `paper/main.pdf` in the complete project archive. The article has a 218-word abstract under the repository counter and eight keywords.

The article contains the exact causal-roster theorems, generic session-separated reduction, executable Ed25519 reference-profile theorem, and key-prefixed BGLS one-session theorem. This is a written proof artifact, not a proof-assistant development, pairing implementation, benchmark, or independent review.

Build with:

```sh
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
```

Successful compilation checks only typesetting and cross-references. The archived finite campaign permanently exceeded its cumulative ceiling, so neither this build nor any historical executable output is scientific reproduction evidence.
