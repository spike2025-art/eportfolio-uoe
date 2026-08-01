# Reproducibility

This document describes how to recreate the computational environment and reproduce
the headline results of the dissertation *Machine Learning Early-Warning Systems for
Banking Crises* (Papachristos, University of Essex Online, 2026).

The central finding — that ML-based early-warning systems fail **prospectively** because
of structural non-stationarity in the data-generating process, not because of model
choice — is reproduced by running the notebook pipeline below end to end.

---

## 1. Environment

The analysis was run under a Conda environment named `Dissertation`.

| Component | Version |
|---|---|
| Python | 3.11.14 |
| interpret (EBM) | 0.7.8 |
| xgboost | 3.2.0 |
| scikit-learn | 1.8.0 |
| shap | 0.50.0 |

These are the pins that materially affect results (the EBM/XGBoost/RF fits and the
SHAP/shape-function outputs). To recreate the full environment exactly, export it from
the machine that produced the results:

```bash
conda activate Dissertation
conda env export --no-builds > environment.yml
```

and commit the resulting `environment.yml` alongside this file. A fresh machine can then
rebuild with:

```bash
conda env create -f environment.yml
conda activate Dissertation
```

> **Note on determinism.** All estimators are instantiated with a fixed `random_state`
> (see the configuration cell at the top of each modelling notebook). EBM shape functions,
> the ROC/PR metrics, and the Stage-1 rankings reproduce deterministically on the pinned
> versions above. FinBERT inference is CPU-deterministic but slow (see §5).

---

## 2. Data sources and hosting policy

This repository follows a **derived-artefacts-only** policy. The two primary raw sources
are *not* redistributed here; they are linked at source and must be obtained from the
original providers under their own terms. Only the processed, analysis-ready files are
hosted in `data/`.

**Primary sources (obtain at source):**

- **JST Macrohistory Database, Release R6** — 18 advanced economies. Download from the
  Jordà-Schularick-Taylor Macrohistory project site.
- **BIS central bank speeches corpus** (1997–2020) — download from the Bank for
  International Settlements (`bis.org/cbspeeches/download.htm`). Sentiment features are
  derived from this corpus with FinBERT.

**Processed files hosted in `data/`:**

| File | Shape | Span | Notes |
|---|---|---|---|
| `df_macro_augmented.csv` | 569 rows × 101 cols | 1989–2020, 18 economies | Stage-1 analytical panel. 37 crisis-positive labels. Contains `iso`, `year`, `crisisjst`, `target_h1/h2/h3`, `term_spread` (+ lags 1–3, raw and `_dm` demeaned) and `tloans_gr` credit growth (+ lags and demeaned). This is the panel the Granger-causality tests (§4.9) run on. |
| `jst_sentiment_master.csv` | 432 rows × 95 cols | 1997–2020 | Raw JST macro fields plus FinBERT sentiment features (e.g. `net_sent_slope4_lag1`). No crisis target or demeaned lags. Used for the sentiment Granger tests. |

---

## 3. Notebook pipeline

The pipeline runs in order, `NB00` → `NB15`. Broad stages:

- **NB00–NB03** — data assembly: load JST R6, build the macro panel, load the BIS speech
  corpus, run FinBERT sentiment inference.
- **NB04–NB05** — feature engineering and model training. `NB05A` trains the tree/boosting
  models (RF, XGBoost); `NB05B` trains the EBM.
- **NB06–NB09** — evaluation: ROC/PR, calibration, SHAP/shape functions, Granger-causality
  and structural-break tests.
- **NB10–NB15** — extensions and robustness: topic-sentiment extension (`NB10C`, null
  result), the 2×2 EBM-vs-XGBoost / macro-vs-sentiment design (`NB12`), EBM hyperparameter
  robustness (`NB13`), leave-one-country-out (`NB14`), and the Chow-type structural-break
  test (`NB15`).

---

## 4. Reproducing the headline results

The dissertation's headline triplet is:

> **EBM AUROC 0.753 in-sample → 0.960 in the 2007 GFC cross-section → 0.333 out-of-sample
> (Split B, strict temporal validation).**

- The **in-sample / cross-validated** Stage-1 metrics are produced in `NB05A`/`NB05B` and
  evaluated in the NB06 evaluation notebooks.
- The **2007 GFC cross-section** case study (215 obs, 11 crisis events) is the cross-sectional
  evaluation in the Stage-2 notebooks.
- The **Split B prospective** collapse (EBM AUROC 0.333, RF 0.481 — both below the 0.75
  benchmark, i.e. sub-random ranking) is the strict pre-GFC / GFC-inclusive temporal split.
  This is the result that carries the thesis: high in-sample flexibility → worse prospective
  generalisation.

---

## 5. Runtime and hardware notes

- **FinBERT inference (NB03)** runs on CPU and takes roughly 3–5 hours over the ~16,600
  BIS speeches. Speeches exceeding FinBERT's 512-token limit are truncated to 512 tokens
  before scoring (this is a documented methodological choice, not a silent drop).
- All modelling and evaluation notebooks run in minutes on a standard laptop; no GPU is
  required.

---

## 6. Reconciliation notes (read before comparing raw notebook output to the dissertation)

Two points where raw notebook output differs from the analytical panel are documented here
so a reproducer does not mistake them for errors:

1. **Sample size (`NB05A` prints 1988 / 39 vs. panel 1989 / 37).** `NB05A`'s console output
   reports an earlier internal counting stage. The **authoritative analytical sample** is the
   `df_macro_augmented.csv` panel: **1989–2020, 569 observations, 37 crisis positives**. The
   dissertation numbers are pinned to this panel; the `NB05A` print is left unaltered so the
   notebook remains faithful to what was actually run.

2. **M3 feature count.** The `M3` (XGBoost, macro + sentiment) model is trained on **61
   features (41 macro + 20 sentiment)**. Some early table captions describe it as 55/14; that
   is a documentation description only and does not affect the fitted model or any reported
   metric.
