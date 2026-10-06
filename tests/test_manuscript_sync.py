"""Narrow regressions for scientific-source drift, not theorem verification."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_artifact import AuditError, check_manuscript_sync, scientific_body


class ManuscriptSyncTests(unittest.TestCase):
    def test_scientific_qualification_changes_are_not_ignored(self):
        source = (r"\begin{abstract}Claim\end{abstract}" + "\n"
                  + "Binary-encoded integer weights.\n"
                  + r"\begin{thebibliography}{10}")
        self.assertNotEqual(scientific_body(source),
                            scientific_body(source.replace("Binary-encoded integer ", "")))

    def test_recursive_figure_and_proof_inputs_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            paper = Path(tmp)
            (paper / "main.tex").write_text(
                r"\begin{abstract}Claim\end{abstract}" + "\n"
                + r"\input{section}" + "\n" + r"\input{project-repository.tex}"
                + "\n" + r"\bibliographystyle{abbrv}", encoding="utf-8")
            (paper / "section.tex").write_text(r"\input{figure}", encoding="utf-8")
            (paper / "figure.tex").write_text("A precedes B.\n", encoding="utf-8")
            analysis = (r"\begin{abstract}Claim\end{abstract}" + "\n"
                        + "A precedes B.\n" + r"\begin{thebibliography}{10}")
            self.assertIn("match", check_manuscript_sync(analysis, paper))
            (paper / "figure.tex").write_text("B precedes A.\n", encoding="utf-8")
            with self.assertRaises(AuditError):
                check_manuscript_sync(analysis, paper)

    def test_standalone_scope_and_blank_line_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("not checked", check_manuscript_sync("", Path(tmp)))
        source = r"\begin{abstract}Claim\end{abstract}" + "\nText.\n"
        self.assertEqual(scientific_body(source + r"\bibliographystyle{abbrv}"),
                         scientific_body(source.replace("\n", "  \n\n")
                                         + r"\begin{thebibliography}{10}"))


if __name__ == "__main__":
    unittest.main()
