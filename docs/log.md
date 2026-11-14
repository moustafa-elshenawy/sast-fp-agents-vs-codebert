
## 2026-11-15: dataset built, token lengths, shortcut baselines

**Done**
- `scripts/build_dataset.py` reads the artifact (labels from `expectedresults-1.2.csv`, alerts from the task JSONs, code from the SWE-agent+Claude `task.md` files) and writes one table, with test names and category folders masked.
- Result: 2,718 cases = 1,303 in the FP pool (all non-vulnerable) + 1,415 in the TP pool (all vulnerable). No label disagrees with its pool folder. 0 of 30,571 flagged lines point at a blank line, so scanner line numbers match the code.
- 4 TP-pool cases have no saved run folder and therefore no code: BenchmarkTest00119, 01480, 02018, 02588. Excluded from modelling. 2,714 usable (1,411 TP, 1,303 FP).
- Exact-duplicate check: 2,710 unique masked files out of 2,714; 4 files shared by two cases, none with mixed labels.

**Token lengths (microsoft/codebert-base tokenizer, `scripts/token_stats.py`)**
- alert text: median 179 tokens (0.4% over 512). Code window: median 861 (76.6% over 512). Whole file: median 1,469 (98.8% over 512). Alert + window: median 1,057; 87.5% over 512 (FP 81.6%, TP 92.9%).
- Consequence: a plain cut at 512 would hit TP cases more often than FP cases. Input is built with fixed token budgets instead (alert about 120, code about 370, flagged lines first). Share of cases losing content is reported by label by `train_codebert.py`.

**Shortcut baselines (`scripts/baselines.py`, logistic regression, out-of-fold, seed 0, untuned)**

| features | random 5-fold AUC | FP pass-through at 77.75% TP kept | leave-one-category-out AUC | pass-through |
|---|---|---|---|---|
| tool flags + count | 0.670 | 0.582 | 0.581 | 0.592 |
| + lengths and counts | 0.796 | 0.316 | 0.739 | 0.373 |
| alert text (word counts) | 0.910 | 0.166 | 0.774 | 0.287 |
| code window (word counts) | 0.978 | 0.018 | 0.770 | 0.452 |
| alert + code | 0.987 | 0.005 | 0.843 | 0.190 |

Reference: base paper best agent (SWE-agent + Claude Sonnet 4) about 0.064 pass-through (83 of 1,303) at 77.75% of TPs kept (not the same evaluation setup).

**Decisions**
- Random split results are reported as in-distribution only. The headline test is leave-one-category-out, with Vul4J (50 alerts) as the outside-the-benchmark check.
- Every CodeBERT result is compared with the word-count baselines, not only with the agents. Code-only and alert-only CodeBERT runs are kept as shortcut controls.
- Recipe is fixed in advance (3 epochs, lr 2e-5, effective batch 16) so nothing is tuned on test data.

**Next**: rebuild dataset with `flag_lines` and `header_offset` columns, timing test of `scripts/train_codebert.py` on the M1, then decide how many folds are affordable (fallback: CodeBERT embeddings + logistic regression).
