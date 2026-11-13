<!--
DRAFT 1 of Section II for the IEEE template. Plain markdown, unnumbered headings (the template numbers them).

Notes for the author (delete before moving into Word):
- Every [VERIFY] tag marks a detail taken from a search listing or page summary. Read the source and fix or remove the tag.
- The reference list needs the same pass: author initials, venues and years come from listings, not from the papers themselves.
- The "This work" row in Table I states the intended design, not results. Update it when results exist.
- Facts about the base paper [1] were checked against its PDF and the released artifact [2].
-->

## Background and Related Work

### Static Analysis Alerts and False Positives

Static application security testing (SAST) tools search source code for patterns and data flows that may indicate vulnerabilities. They raise many alerts that do not correspond to real vulnerabilities, and each alert must be triaged by a person. The OWASP Benchmark v1.2 is a widely used Java test suite for studying this problem [3]. It contains 2,740 servlet test cases in 11 CWE categories, of which 1,415 are vulnerable and 1,325 are not [3]. Xiong and Zhang report that the union of four SAST tools (CodeQL, Semgrep, SonarQube and Joern) flags 1,303 of the 1,325 non-vulnerable cases, a baseline false-positive rate of 98.3% [1].

### Learning-Based Alert Filtering

A long line of work treats alert filtering as supervised classification, often called actionable warning identification. A survey covers 51 primary studies of machine learning for this task [4] [VERIFY]. Kharkar et al. compared a fine-tuned transformer encoder with feature-based and generative baselines for filtering warnings from a static analyzer [5] [VERIFY]. A feasibility study fine-tuned several pre-trained code models, including CodeBERT, on SpotBugs warnings and found that giving the model the enclosing method worked better than giving it only the flagged line [6] [VERIFY]. Xue et al. fine-tuned a pre-trained model with weak supervision and discussed how noisy "actionable" labels can be [7] [VERIFY]. These studies concern general bug warnings rather than security alerts from several tools, and they predate LLM agents.

### LLM-Based Alert Filtering

Wen et al. used a large language model (LLM) as a one-shot inspector of static bug warnings [8] [VERIFY]. Later work added more context or structure. LLM4FPM supplies code slices and file dependencies to the model and evaluates on the Juliet suite and eight C/C++ projects [9]. LLM4PFA checks path feasibility with LLM-generated constraints [10]. On the OWASP Benchmark, Wagner et al. prompted LLMs under a requirement to keep every true positive [11] [VERIFY]. ZeroFalse gives the model CodeQL data-flow traces and CWE-specific rubrics, and evaluates on 1,974 OWASP cases that CodeQL alerted on [12]. QASecClaw is a multi-agent system that filters Semgrep findings and reports that false positives fell from 560 to 64 while 40 of 1,273 true positives were lost [13]. In the papers we read, these systems are compared with the raw analyzer or with other LLM methods, not with a model fine-tuned on the filtering task.

### Agentic Filtering: The Base Study

Xiong and Zhang compare three agent frameworks (Aider, OpenHands and SWE-agent) with three backbone models (Claude Sonnet 4, GPT-5 and DeepSeek Chat) on one task: given a SAST alert and access to the code base, decide whether the alert is a true vulnerability or a false alarm [1]. The best configuration, SWE-agent with Claude Sonnet 4, lowers the residual false-positive rate on OWASP from 98.3% to 6.3%, a drop of 92.1 percentage points. The cost is that it labels 314 of 1,411 completed true-vulnerability runs (22.25%) as false alarms. These misses are concentrated in a few CWEs, including CWE-327 (77.17%), CWE-328 (84.50%) and CWE-501 (77.11%) [1]. Cost per task ranges from about $0.003 to about $0.19 across configurations [1]. The authors release the saved predictions and trajectories [2]. They list CWE-aware, cost-adaptive agent strategies and human-in-the-loop auditing as future work [1].

### Learned Models Versus LLMs

A few studies compare learned models with LLMs. Ni et al. triage taint flows reported by a dynamic analyzer for Node.js packages. They compare classical machine learning, a graph neural network, zero-shot LLMs and fine-tuned LLMs, and report that supervised models matched or exceeded zero-shot LLMs, with a gradient-boosting model within about one F1 point of the best model at much lower compute [14] [VERIFY]. Du et al. study LLM-based filtering in an industrial setting and include learning-based baselines that were applied without fine-tuning on the filtering task, and these performed poorly [15] [VERIFY]. A TU Delft master's thesis reports that classical models outperformed Claude models on a Java warning dataset at lower cost [16] [VERIFY]. None of these compares a model fine-tuned on security alert filtering with LLM agents on the same alerts.

### Positioning of This Work

Table I summarizes how the closest works differ. This study keeps the alerts, labels and agent verdicts of [1] fixed and adds one new arm: a CodeBERT model fine-tuned to decide, from an alert and its code, whether the alert is a true vulnerability. Both arms are scored on the same alerts, and true-positive retention is reported next to the residual false-positive rate. In the literature we reviewed, we found no study that does this on the OWASP Benchmark.

TABLE I. COMPARISON WITH CLOSEST RELATED WORK

| Work | Model families compared | Security alerts | Fine-tuned on filtering | Reports TP loss |
|---|---|---|---|---|
| Xiong and Zhang [1] | LLM agents, vanilla LLM | Yes | No | Yes |
| ZeroFalse [12] | LLMs | Yes | No | Recall only |
| QASecClaw [13] | Multi-agent LLM | Yes | No | Yes |
| Wagner et al. [11] | Prompted LLMs | Yes | No | Yes |
| Du et al. [15] | LLMs, off-the-shelf DL | No (general bugs) | No | ? |
| Ni et al. [14] | ML, GNN, LLMs | Yes (dynamic analysis) | Yes | ? |
| PTM study [6] | Fine-tuned code models | No (general bugs) | Yes | ? |
| This work | LLM agents, fine-tuned CodeBERT | Yes | Yes | Yes |

### Evaluation Caveats

Three caveats shape how results should be read. First, the OWASP Benchmark is synthetic and generated from templates, so a model can score well by learning template regularities; we therefore add code-only, alert-only and tool-agreement baselines. Second, the alert pools differ across studies. The pool in [1] contains 1,303 false positives from four tools, while [12] starts from 525 CodeQL-alerted false positives and [13] from 560 Semgrep false positives, so their numbers cannot be compared directly. The same CWE can look easy in one pool and hard in another. Third, labels are not always reliable, as discussed in [7]; here the OWASP ground truth is taken as given.

## References (draft, IEEE style)

[1] Y. Xiong and T. Zhang, "Sifting the noise: A comparative study of LLM agents in vulnerability false positive filtering," *Proc. ACM Softw. Eng.*, ISSTA, 2026, doi: 10.1145/3832100.

[2] "ISSTA 2026 artifact package for Sifting the Noise: A comparative study of LLM agents in vulnerability false positive filtering," Zenodo, 2026, doi: 10.5281/zenodo.21282004.

[3] OWASP Foundation, "OWASP Benchmark Project," version 1.2. [Online]. Available: https://owasp.org/www-project-benchmark/

[4] X. Ge et al., "Machine learning for actionable warning identification: A comprehensive survey," 2023, arXiv:2312.00324. [VERIFY]

[5] A. Kharkar et al., "Learning to reduce false positives in analytic bug detectors," in *Proc. Int. Conf. Softw. Eng. (ICSE)*, 2022, arXiv:2203.09907. [VERIFY]

[6] "Pre-trained model-based actionable warning identification: A feasibility study," 2024, arXiv:2403.02716. [VERIFY authors and venue]

[7] Z. Xue et al., "Actionable warning is not enough: Recommending valid actionable warnings with weak supervision," in *Proc. ICSE*, 2026, arXiv:2511.12229. [VERIFY]

[8] W. Wen et al., "Automatically inspecting thousands of static bug warnings with large language model: How far are we?," *ACM Trans. Knowl. Discov. Data*, 2024, doi: 10.1145/3653718. [VERIFY]

[9] J. Chen et al., "Utilizing precise and complete code context to guide LLM in automatic false positive mitigation," 2024, arXiv:2411.03079. [VERIFY]

[10] X. Du et al., "Minimizing false positives in static bug detection via LLM-enhanced path feasibility analysis," 2025, arXiv:2506.10322.

[11] J. Wagner et al., "Towards effective complementary security analysis using large language models," arXiv:2506.16899. [VERIFY authors and year]

[12] M. Iranmanesh et al., "ZeroFalse: Improving precision in static analysis with LLMs," 2025, arXiv:2510.02534.

[13] M. R. Ameen, M. T. U. Alam, and A. Islam, "QASecClaw: A multi-agent LLM approach for false positive reduction in static application security testing," 2026, arXiv:2605.01885.

[14] R. Ni et al., "Learning to triage vulnerability reports from program analysis: An empirical study in Node.js," arXiv:2510.20739. [VERIFY venue and year]

[15] X. Du et al., "Reducing false positives in static bug detection with LLMs: An empirical study in industry," 2026, arXiv:2601.18844. [VERIFY]

[16] Master's thesis on machine learning versus LLMs for static-analysis warning prioritization, TU Delft, 2026. [VERIFY author and title]
