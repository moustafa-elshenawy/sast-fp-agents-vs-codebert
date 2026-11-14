
## C1 (preliminary): the OWASP Benchmark can be largely solved by word counts on a random split

**Statement.** On the 2,714 usable cases, a logistic regression on word counts of the scanner alert plus the masked code window reaches AUC 0.987 and lets 0.5% of false positives through at 77.75% of true positives kept, under random 5-fold cross-validation. With a whole CWE family held out, the same model reaches AUC 0.843 and 19.0% pass-through.

**Status.** Preliminary. From my own run of `scripts/baselines.py` (seed 0, default settings, 2026-11-15). Not independently checked.

**Why it matters.** The benchmark cases are generated from templates, so near-identical siblings land in both training and test under a random split. A fine-tuned model beating the agents on a random split would show template learning, not understanding. The headline comparison therefore uses leave-one-category-out.

**Caveats (do not drop these when quoting).**
- Untuned baseline, one seed.
- Pooled out-of-fold scores mix folds with different calibration; the threshold is chosen on the same scores (slightly optimistic).
- The 0.064 pass-through of the best agent comes from the base paper's own evaluation, not from this setup. The agents also see the whole code base, not a masked window.
- Exact duplicates are ruled out (2,710 unique files of 2,714); near-duplicates are not.

## C2 (preliminary): counts alone carry label signal

Tool flags and counts only give AUC 0.670 (random) and 0.581 (leave-category-out). Adding finding counts and lengths gives 0.796 and 0.739. Cases with more findings are more often true positives. Status and caveats as C1.

## C3 (preliminary): length differs by label, so naive truncation is unsafe

Alert + code window exceeds 512 CodeBERT tokens in 81.6% of FP cases and 92.9% of TP cases (87.5% overall). A hard cut at 512 would therefore remove content from TP cases more often. Whether this becomes a usable shortcut is not yet tested; the code-only and alert-only CodeBERT controls address it.
