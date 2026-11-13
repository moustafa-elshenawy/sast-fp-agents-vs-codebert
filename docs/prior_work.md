# Prior work register (working file for Section 2)

Project: controlled comparison of LLM agents and a fine-tuned CodeBERT model for filtering SAST false positives (OWASP Benchmark v1.2).

Status legend:

- **V** = checked against the full text or the primary page in this project.
- **S** = read from the paper's own page or a summary of it, not the full text. Read the paper before citing any number from it.
- **N** = from your notes only. Not found or not looked at yet.

## A. Base paper

| Key | Reference | Status |
|---|---|---|
| Xiong2026 | Y. Xiong and T. Zhang, "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering," Proc. ACM Softw. Eng. (ISSTA 2026), art. ISSTA009, Oct. 2026. DOI 10.1145/3832100. arXiv:2601.22952 | V |
| Xiong2026-artifact | Replication package, Zenodo, version issta2026-ae-v3-kick-the-tires, DOI 10.5281/zenodo.21282004 (all versions: 10.5281/zenodo.18420284) | V (downloaded, checksum verified) |

Reproduced from the stored data: 83 of 1,303 FP-pool cases still labeled TP (6.26% of 1,325 non-vulnerable cases); 314 of 1,411 completed true-vulnerability runs labeled FP (22.25%), for SWE-agent + Claude Sonnet 4.

Wording rule: the paper's "92.1% reduction" is a drop of 92.1 percentage points (98.3% to 6.3%). Write it that way.

## B. Supervised or learned models compared with LLMs (closest to this project)

| Key | Reference | What it did | Relation to this project | Status |
|---|---|---|---|---|
| Ni2026 | R. Ni et al., "Learning to Triage Vulnerability Reports from Program Analysis: An Empirical Study in Node.js," arXiv:2510.20739 (page says ASE 2026; confirm) | Triage of taint flows from a dynamic analyzer in npm packages (1,883 packages). Compared classical ML, a graph neural network, zero-shot commercial LLMs and fine-tuned local LLMs | Security-focused learned-vs-LLM comparison. Fine-tuned LLM best (F1 0.915); XGBoost within about one F1 point at far lower compute; zero-shot LLMs trailed supervised models. Dynamic analysis, not static SAST on Java; no agents; no OWASP | S |
| Du2026 | X. Du et al., "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry," arXiv:2601.18844, Jan. 2026 | 433 alarms from an enterprise analyzer. Prompting, hybrid LLM+static methods, and learning baselines (Devign, ReGVD, LLMAO, LineVul) | Learning baselines were applied off-the-shelf, not fine-tuned on the filtering task, and scored 0.36-0.44 accuracy; LineVul labeled nearly everything FP. General bug types, data not released | S |
| TUDelft2026 | V.Y. Ning, master's thesis, TU Delft, 2026 | Random Forest and Logistic Regression vs Claude models on the NASCAR Java warning dataset | Classical ML reported better and cheaper. Thesis, not peer-reviewed. No agents, not security SAST | S |
| Kharkar2022 | A. Kharkar et al., "Learning to Reduce False Positives in Analytic Bug Detectors," ICSE 2022, arXiv:2203.09907 | Fine-tuned encoder vs feature-based model vs GPT-2-style model on Infer warnings | Precedent for a fine-tuned encoder as a filter. Null-dereference and resource-leak warnings; no modern LLMs | S |
| PTM2024 | Pre-trained model-based actionable warning identification, arXiv:2403.02716 (title and venue to be confirmed) | CodeBERT, GraphCodeBERT, CodeT5, UniXcoder, CodeGPT on 10,140 SpotBugs warnings | Fine-tuned CodeBERT precedent. Enclosing-method context beat line-only context | S |
| Xue2026 | Z. Xue et al., "Actionable Warning Is Not Enough...," ICSE 2026, arXiv:2511.12229 | Fine-tuned UniXcoder on Infer and Flawfinder warnings (C) | Evidence that "actionable" labels are noisy. Not LLM vs DL | S |
| Ge2024 | X. Ge et al., "Machine Learning for Actionable Warning Identification: A Comprehensive Survey," arXiv:2312.00324 | Survey of 51 primary studies | Background for the learning-based filtering subsection | S |

## C. LLM and agent filtering of SAST alerts (no fine-tuned DL baseline in any of them)

| Key | Reference | Alert pool and baseline | Reported result | Status |
|---|---|---|---|---|
| Xiong2026 | (base paper) | OWASP v1.2. Union of 4 tools: 1,303 FP cases, 1,415 TP cases | Best config: residual FPR 6.3%; 22.25% of TPs suppressed (one config) | V |
| ZeroFalse | M. Iranmanesh et al., "ZeroFalse: Improving Precision in Static Analysis with LLMs," arXiv:2510.02534 (v1 Oct 2025; page lists JACM) | OWASP subset of 1,974 cases that triggered a CodeQL alert (1,449 TP, 525 FP), 10 CWEs; plus 58 alerts from 7 Java projects | F1 0.912 (Grok-4) on OWASP; 0.955 (GPT-5) on the 58-alert set. No explicit count of suppressed TPs | S |
| QASecClaw | M.R. Ameen et al., "QASecClaw: A Multi-Agent LLM Approach for False Positive Reduction in SAST," arXiv:2605.01885, May 2026 | OWASP v1.2, all 2,740 cases. Semgrep only (560 FPs, 1,273 TPs flagged) | F1 90.93% vs 78.39% for Semgrep alone; FPs 560 to 64; 40 of 1,273 TPs lost (3.1%). CWE-501 got worse (F1 0.768 to 0.593). File-level evaluation unit | S |
| Wagner2025 | J. Wagner et al., "Towards Effective Complementary Security Analysis using Large Language Models," arXiv:2506.16899 (year to confirm) | OWASP v1.2, SpotBugs + FindSecBugs findings; 403-finding test split | Zero missed TPs at conservative thresholds; self-consistency filtered 62.5% of FPs at 100% TPR | S |
| LLM4SA | W. Wen et al., "Automatically Inspecting Thousands of Static Bug Warnings with Large Language Model: How Far Are We?," ACM TKDD 2024, arXiv:2306.12643 (title and DOI 10.1145/3653718 from search listings; confirm) | General static bug warnings | One-shot LLM as semantic inspector | S |
| LLM4FPM | J. Chen et al., "Utilizing Precise and Complete Code Context to Guide LLM in Automatic False Positive Mitigation," arXiv:2411.03079 | Juliet (7,194 cases) and 8 C/C++ projects; only LLM4SA as baseline | F1 about 97-99% on Juliet; abstract overstates one case | S |
| LLM4PFA | X. Du et al., "Minimizing False Positives in Static Bug Detection via LLM-Enhanced Path Feasibility Analysis," arXiv:2506.10322, 2025 | 364 C warnings; LLM-based baselines only | Filters 72-96% of FPs; missed 3 of 45 true bugs | S |

**The pools differ, so these numbers are not comparable with each other.** The base paper filters a pool of 1,303 FP cases from four tools. ZeroFalse starts from CodeQL-alerted cases only, with 525 FPs. QASecClaw starts from Semgrep only, with 560 FPs. The same CWE can look easy in one pool and hard in another: QASecClaw reports CWE-327 F1 of 99.61% because Semgrep produced almost no FPs there, while the base paper's agents suppress many true cryptographic cases. Never put these results in one table without stating the pool.

## D. Detection models (a different task, mentioned only for contrast)

| Key | Reference | Note | Status |
|---|---|---|---|
| Aegis2026 | S. Fang et al., "Aegis: From Clues to Verdicts," arXiv:2603.20637, Mar. 2026 | Vulnerability detection on PrimeVul, not alert filtering. Fine-tuned CodeBERT, CodeT5 and UniXcoder baselines were trained for detection; the best fine-tuned model had a 58.39% false-positive rate | S |

## E. Not found or not yet checked

- **ObliVul:** I could not find a paper under this name. The search returned only unrelated papers. Check where your note came from. Do not cite it until you find it.
- Not yet looked at: Argus, AuditGPT, SastBench, TRIAGE-CPG, the 2026 survey "Reducing False Positives in Vulnerability Detection," VulBERTa, FP-Predictor.
- Standard references still to add: CodeBERT (Feng et al., 2020); SWE-agent, OpenHands and Aider (cited in the base paper); the OWASP Benchmark project.
- Do not cite: a 2026 *Frontiers of Computer Science* paper on LLM warning filtering. Its page carries a retraction notice.

## F. What the literature allows you to claim

Do NOT write:
- "This is the first comparison of LLMs and deep learning for filtering static-analysis warnings." Du2026, TUDelft2026 and Ni2026 are counterexamples.
- That nobody has used true-positive retention as a requirement. Wagner2025 did.
- Any claim about the final result before it exists.

Defensible, if the later reading confirms it. About 15 searches found no study that fine-tunes a code encoder on OWASP alert filtering and compares it against the base paper's agent verdicts on the same alerts. That is a statement about my search, not proof that none exists.
- A same-alert comparison on public security data, using released agent verdicts.
- The deep learning arm is fine-tuned on the filtering task itself.
- True-positive retention and residual false-positive rate are reported together.
- Shortcut checks and a failure-mode analysis.

## G. A calibrated expectation (not a result)

Ni2026 and TUDelft2026 both found supervised or classical models matching or beating zero-shot LLMs at triage, at much lower cost. On a template-generated benchmark like OWASP, a fine-tuned model may well match the agents in-distribution. If so, the informative parts of this project are what the headline number hides: whether the result survives the shortcut checks, how TP retention compares at matched operating points, whether performance holds on held-out CWEs and on the 50 Vul4J alerts, cost per alert, and where each approach fails.

## H. Section 2 outline (IEEE section II, Background and Related Work)

A. Static analysis alerts and the false-positive problem. [Xiong2026, OWASP]
B. Learning-based alert filtering. [Ge2024, Kharkar2022, PTM2024, Xue2026]
C. LLM-based alert filtering. [LLM4SA, LLM4FPM, LLM4PFA, Wagner2025, ZeroFalse, QASecClaw]
D. Agentic filtering and the base study. [Xiong2026]
E. Studies that compare learned models with LLMs. [Ni2026, Du2026, TUDelft2026] and what they do not settle.
F. Positioning table. Rows are the works above. Columns: task unit, model family, security SAST or general warnings, public data, fine-tuned on the filtering task, reports TP retention, alert pool. Use "?" for any cell not yet verified.
G. Evaluation caveats: synthetic template-generated benchmark, differing pools, label quality.

## I. Week 8 presentation outline (about 6 slides)

1. Problem: SAST false positives and the cost of triage.
2. Base paper: what it did, the headline numbers, the TP-retention trade-off.
3. Research question: which filter is better, an iterative LLM agent or a fine-tuned code encoder, on effectiveness, cost and failure modes.
4. Related work and the gap (use table H.F). State that learned-vs-LLM comparisons exist and where this one differs.
5. Plan: data from the artifact, CodeBERT trained on alert plus code, shortcut checks, matched-retention comparison.
6. Risks and timeline: benchmark shortcuts, hardware limits, weeks 8 to 13.

## J. To do before citing anything marked S or N

1. Read each S item in full. Confirm title, venue, year and the numbers.
2. Confirm Wagner2025's year, PTM2024's title and venue, Ni2026's venue, and the LLM4SA DOI.
3. Locate ObliVul or drop it.
4. Read the abstracts of Argus, AuditGPT, SastBench and TRIAGE-CPG.
