# Machine Learning Early-Warning Systems for Banking Crises

Supporting code, data, figures and artefacts for the MSc Artificial Intelligence
dissertation of **Pavlos Papachristos** (University of Essex Online, 2026).

This folder backs the *Computing Dissertation Conference Space* section of the ePortfolio
at **https://spike2025-art.github.io/eportfolio-uoe**.

---

## The result in one line

ML early-warning systems (EWS) for banking crises **fail prospectively because of
structural non-stationarity in the data-generating process — not because of model choice**.
A highly flexible learner (an Explainable Boosting Machine) that ranks near-perfectly in
sample collapses to sub-random ranking under strict temporal validation:

> **EBM AUROC 0.753 in-sample → 0.960 in the 2007 GFC cross-section → 0.333 out-of-sample
> (Split B).**

The gain in in-sample flexibility is exactly what makes the model *worse* out of sample.
The dissertation demonstrates this across leave-one-country-out validation, a 2×2
algorithm-vs-feature-set design, EBM shape-function instability, and a Chow-type
structural-break test.

---

## Data

- **Panel:** 18 advanced economies, 1989–2020, 569 observations, 37 crisis-positive labels
  (the 2007–09 GFC accounts for ~65% of positives).
- **Sources:** the [JST Macrohistory Database R6](https://www.macrohistory.net/database/)
  and FinBERT-processed [BIS central bank speeches](https://www.bis.org/cbspeeches/download.htm).

**Hosting policy — derived artefacts only.** The two raw sources above are *not*
redistributed here; download them at source. Only the processed, analysis-ready files are
hosted, in `data/`:

- `df_macro_augmented.csv` — Stage-1 analytical panel (569 × 101).
- `jst_sentiment_master.csv` — sentiment-feature panel (432 × 95).

See [`environment/REPRODUCIBILITY.md`](environment/REPRODUCIBILITY.md) for full schema and
provenance.

---

## Repository layout

```
Dissertation_eportfolio/
├── notebooks/      16 cleaned Jupyter notebooks (NB00–NB15)
├── figures/        17 figures used in the write-up (fig4_1 … figA_2, 01_crisis_frequency)
├── data/           2 processed CSVs (derived artefacts only)
├── artefacts/      final dissertation PDF, viva presentation, narration
└── environment/    REPRODUCIBILITY.md (+ environment.yml)
```

---

## Reproducing the analysis

The full environment and step-by-step instructions are in
[`environment/REPRODUCIBILITY.md`](environment/REPRODUCIBILITY.md). In brief:

```bash
conda env create -f environment/environment.yml   # Python 3.11, interpret/xgboost/sklearn/shap pinned
conda activate Dissertation
# run notebooks NB00 → NB15 in order
```

Key packages: `interpret 0.7.8`, `xgboost 3.2.0`, `scikit-learn 1.8.0`, `shap 0.50.0`.

---

## Artefacts

- **Dissertation (PDF)** — full write-up.
- **Viva presentation** — slide deck.
- **Narration** — spoken-summary script (`.txt`) and audio (`.mp3`).

Exact filenames are listed in the *Computing Dissertation Conference Space* section of the
live ePortfolio.

---

## Author

Pavlos Papachristos · MSc Artificial Intelligence, University of Essex Online
ePortfolio: https://spike2025-art.github.io/eportfolio-uoe
