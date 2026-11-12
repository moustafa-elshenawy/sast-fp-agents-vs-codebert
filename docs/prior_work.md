# Prior work register (working file for Section 2)

Project: controlled comparison of LLM agents and a fine-tuned CodeBERT model for filtering SAST false positives (OWASP Benchmark v1.2).

Status legend (how well each entry has been checked so far):

- **V** = checked against the full text or the primary page in this project.
- **S** = seen only through a search result or a page summary. Read the paper before citing any number from it.
- **N** = taken from your own notes. Not looked at yet.

## A. Base paper

| Key | Reference | Status |
|---|---|---|
| Xiong2026 | Y. Xiong and T. Zhang, "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering," Proc. ACM Softw. Eng. (ISSTA 2026), art. ISSTA009, Oct. 2026. DOI 10.1145/3832100. arXiv:2601.22952 | V |
| Xiong2026-artifact | Replication package, Zenodo, version issta2026-ae-v3-kick-the-tires, DOI 10.5281/zenodo.21282004 (all versions: 10.5281/zenodo.18420284) | V (downloaded, checksum verified) |

Numbers already reproduced from the stored data: 83 of 1,303 FP-pool cases still labeled TP (6.26% over 1,325 non-vulnerable cases); 314 of 1,411 completed true-vulnerability runs labeled FP (22.25% miss rate), SWE-agent + Claude Sonnet 4.

Wording rule: the paper's "92.1% reduction" is a drop of 92.1 percentage points (98.3% to 6.3%). Write it that way.

## B. Closest comparisons found so far (first pass, summaries only)

| Key | Reference | What it did | Relation to this project | Status |
|---|---|---|---|---|
| Du2026 | X. Du et al., "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry," arXiv:2601.18844, Jan. 2026 | 433 alarms from an enterprise analyzer (Tencent). Prompting, hybrid LLM+static methods, and learning baselines (Devign, ReGVD, LLMAO, LineVul) | Closest overlap. Its learning baselines were applied off-the-shelf, not fine-tuned on the filtering task, and scored 0.36-0.44 accuracy; LineVul labeled nearly everything FP. General bug types, data not released | S |
| TUDelft2026 | V.Y. Ning, master's thesis, TU Delft, 2026 (ML vs LLMs for ASAT warning prioritization) | Random Forest and Logistic Regression vs Claude models on the NASCAR Java warning dataset | Classical ML reported better and cheaper. Thesis, not peer-reviewed. No agents, not security SAST | S |
| Wagner2025 | J. Wagner et al., "Towards Effective Complementary Security Analysis using Large Language Models," arXiv:2506.16899 | Prompted LLMs on OWASP Benchmark v1.2 (SpotBugs + FindSecBugs findings) with a "keep every true positive" goal | Prior framing of true-positive retention as a requirement. No fine-tuned DL baseline. Year to be confirmed | S |
| Kharkar2022 | A. Kharkar et al., "Learning to Reduce False Positives in Analytic Bug Detectors," ICSE 2022, arXiv:2203.09907 | Fine-tuned encoder vs feature-based model vs GPT-2-style model on Infer warnings | Precedent for a fine-tuned encoder as a filter. Null-dereference and resource-leak warnings, not security; no modern LLMs | S |
| PTM2024 | Pre-trained model-based actionable warning identification, arXiv:2403.02716 (title and venue to be confirmed) | CodeBERT, GraphCodeBERT, CodeT5, UniXcoder, CodeGPT on 10,140 SpotBugs warnings | Fine-tuned CodeBERT precedent. Reported that enclosing-method context beats line-only context | S |
| Xue2026 | Z. Xue et al., "Actionable Warning Is Not Enough: Recommending Valid Actionable Warnings with Weak Supervision," ICSE 2026, arXiv:2511.12229 | Fine-tuned UniXcoder on Infer and Flawfinder warnings (C) | Evidence that "actionable" labels are noisy. Not LLM vs DL | S |
| Ge2024 | X. Ge et al., "Machine Learning for Actionable Warning Identification: A Comprehensive Survey," arXiv:2312.00324 | Survey of 51 primary studies | Background for the learning-based filtering subsection | S |
| ZeroFalse | "ZeroFalse: Improving Precision in Static Analysis with LLMs," arXiv:2510.02534 | LLM filtering with structured SAST output | Listed in your notes as 0.912 F1 on OWASP; not yet checked | N (title seen in search) |

Do not cite: a 2026 *Frontiers of Computer Science* paper on LLM warning filtering. Its page carries a retraction notice.

## C. References from your notes (not yet looked at)

LLM4SA (Wen et al., TKDD 2024); ObliVul (2026); QASecClaw (arXiv 2026); Argus; AuditGPT; SastBench (2026); TRIAGE-CPG (2026); the 2026 survey "Reducing False Positives in Vulnerability Detection" (Zenodo); Aegis (2026); CodeBERT, VulBERTa and GNN-on-CPG approaches; FP-Predictor.

Standard references to add and verify: the CodeBERT paper (Feng et al., 2020); SWE-agent, OpenHands and Aider (cited in the base paper); the OWASP Benchmark project.

## D. What the literature allows you to claim

Do NOT write:
- "This is the first comparison of LLMs and deep learning for filtering static-analysis warnings." Du2026 and TUDelft2026 are counterexamples.
- Any claim that nobody has used the true-positive-retention framing. Wagner2025 did.
- Any claim of the final result before it exists.

Defensible, if the later reading confirms it:
- A same-alert comparison on public security data (OWASP Benchmark v1.2), using released agent verdicts from the base paper's artifact.
- The deep learning arm is fine-tuned on the filtering task itself (alert plus code to TP/FP), which the off-the-shelf baselines in Du2026 were not.
- True-positive retention and residual false-positive rate are reported together.
- Shortcut checks (code-only, alert-only, tool-agreement baselines) and a failure-mode analysis.

Honest limits to state: OWASP Benchmark is synthetic and template-generated; the base paper's agent verdicts exist for all configurations on the FP pool but TP-side verdicts exist for one configuration only; the code input comes from the artifact's own task files.

## E. Section 2 outline (IEEE section II, Background and Related Work)

A. Static analysis alerts and the false-positive problem. Alert fatigue, OWASP Benchmark, why filtering matters. [Xiong2026 background, OWASP]
B. Learning-based alert filtering. Actionable warning identification, feature-based models, fine-tuned code encoders. [Ge2024, Kharkar2022, PTM2024, Xue2026]
C. LLM-based alert filtering. One-shot prompting and hybrid pipelines. [LLM4SA, Wagner2025, ZeroFalse, Du2026]
D. Agentic filtering and the base study. What Aider, OpenHands and SWE-agent were asked to do, the evaluation, the main numbers and the limitations the authors state. [Xiong2026]
E. Comparisons between the two families. [Du2026, TUDelft2026] and what they do not settle.
F. Positioning. One IEEE table comparing the works on: task unit, model family, security SAST or general warnings, public data, fine-tuned on the filtering task, reports TP retention. Use "?" for any cell not yet verified.
G. Evaluation caveats: label quality, benchmark artifacts, template-generated code.

## F. Week 8 presentation outline (about 6 slides)

1. Problem: SAST false positives and the cost of triage.
2. Base paper: what it did, the headline numbers, and the TP-retention trade-off.
3. Research question: which filter is better, an iterative LLM agent or a fine-tuned code encoder, on effectiveness, cost and failure modes.
4. Related work and the gap (use table F).
5. Plan: data from the artifact, CodeBERT trained on alert plus code, shortcut checks, matched-retention comparison.
6. Risks and timeline: benchmark shortcuts, hardware limits, weeks 8 to 13.

## G. To do before citing anything marked S or N

1. Read each S item in full. Confirm title, venue, year and the numbers.
2. Confirm Wagner2025's year and PTM2024's title and venue.
3. Search specifically for ZeroFalse, QASecClaw, LLM4SA and ObliVul and read their abstracts.
4. One more search for any comparison of a fine-tuned code encoder against LLM agents on security SAST alerts.
