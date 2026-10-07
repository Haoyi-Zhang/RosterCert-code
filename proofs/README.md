# Standalone article source

`analysis.tex` is a recursively inlined, self-contained copy of the current article. It contains no `\input`, BibTeX invocation, project-directory dependency, repository URL, or network dependency. Its bibliography is embedded from the final generated `main.bbl`.

`analysis.pdf` is the 37-page rendering of `analysis.tex`. The source retains 80 cited references and eight keywords; its abstract and scientific body match the manuscript source. Code Availability is intentionally omitted from this standalone copy.

The article contains the exact causal-roster theorems, generic session-separated reduction, executable Ed25519 reference-profile theorem, and key-prefixed BGLS one-session theorem. This is a written proof artifact, not a proof-assistant development, pairing implementation, benchmark, or independent review.

Build with:

```sh
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
```

Successful compilation checks only typesetting and cross-references. The archived finite campaign permanently exceeded its cumulative ceiling, so neither this build nor any historical executable output is scientific reproduction evidence.
