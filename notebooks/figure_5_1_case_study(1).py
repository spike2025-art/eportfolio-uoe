"""
Figure 5.1: Case Study Feature Evidence
Spain / Sweden / UK  —  2004-2006 macro-financial feature comparison

Run from:   C:\Users\Owner\OneDrive\dissertation\
Conda env:  dissertation   (or topic_sentiment)

Output:     figures\figure_5_1_case_study_features.png
            Ready to insert into Discussion_Chapter5_v5.docx
            between Table 5.1 and Section 5.4.1

Usage:
    python figure_5_1_case_study.py
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os, sys

# ── 1. Locate the macro panel ─────────────────────────────────────────────────
CANDIDATE_PATHS = [
    r"data\processed\df_macro_augmented.csv",
    r"data/processed/df_macro_augmented.csv",
    r"df_macro_augmented.csv",
    r"Chapter_4_Results\df_macro_augmented.csv",
]

df = None
for p in CANDIDATE_PATHS:
    if os.path.exists(p):
        df = pd.read_csv(p)
        print(f"Loaded: {p}  ({df.shape[0]} rows, {df.shape[1]} cols)")
        break

if df is None:
    sys.exit(
        "\nERROR: df_macro_augmented.csv not found.\n"
        "Copy it to the dissertation root folder and re-run, or update\n"
        "CANDIDATE_PATHS at the top of this script with the correct path."
    )

# ── 2. Subset and compute 2004-2006 averages ─────────────────────────────────
COUNTRIES = ['GBR', 'SWE', 'ESP']
YEARS     = [2004, 2005, 2006]
subset    = df[df['iso'].isin(COUNTRIES) & df['year'].isin(YEARS)]

if subset.empty:
    sys.exit("ERROR: No rows found for GBR/SWE/ESP in 2004-2006. "
             "Check the 'iso' and 'year' column names in your CSV.")

data = {}
for c in COUNTRIES:
    s = subset[subset['iso'] == c]
    data[c] = {
        'credit_raw':  round(s['tloans_gr_lag1'].mean() * 100, 1),   # % p.a.
        'credit_dm':   round(s['tloans_gr_lag1_dm'].mean(), 3),       # demeaned
        'hp_raw':      round(s['hpnom_gr_lag1'].mean() * 100, 1),     # % p.a.
        'ts_dm':       round(s['term_spread_lag1_dm'].mean(), 3),     # pp demeaned
        'stir_dm':     round(s['stir_lag1_dm'].mean(), 3),            # pp demeaned
    }

# Verification print
print("\n2004-2006 averages used in figure:")
print(f"{'Feature':<32} {'ESP':>8} {'SWE':>8} {'GBR':>8}")
print("-" * 60)
KEYS  = ['credit_raw', 'credit_dm', 'hp_raw', 'ts_dm', 'stir_dm']
LBLS  = ['Credit growth (raw, %)', 'Credit growth (demeaned)',
         'House price growth (raw, %)', 'Term spread lag1 (dem., pp)',
         'Short rate lag1 (dem., pp)']
for k, lbl in zip(KEYS, LBLS):
    print(f"{lbl:<32} {data['ESP'][k]:>8} {data['SWE'][k]:>8} {data['GBR'][k]:>8}")

# ── 3. Colour palette (consistent with dissertation figures) ─────────────────
COLORS = {
    'ESP': '#2166ac',   # steel blue   — Spain / correct hit
    'SWE': '#4dac26',   # green        — Sweden / true positive
    'GBR': '#d01c8b',   # magenta      — UK / false negative
}
C_LEGEND = {
    'ESP': 'Spain (ESP)  —  correct hit',
    'SWE': 'Sweden (SWE)  —  true positive \u2020',
    'GBR': 'UK (GBR)  —  false negative',
}
PANEL_TITLES = [
    'Credit growth\nraw (% p.a.)',
    'Credit growth\ndemeaned',
    'House price growth\nraw (% p.a.)',
    'Term spread lag1\ndemeaned (pp)',
    'Short-term rate lag1\ndemeaned (pp)',
]

# ── 4. Build figure ───────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 5, figsize=(15, 5.5))
fig.patch.set_facecolor('white')

x     = np.array([0, 1, 2])
WIDTH = 0.55

for ax, key, title in zip(axes, KEYS, PANEL_TITLES):
    vals       = [data['ESP'][key], data['SWE'][key], data['GBR'][key]]
    bar_colors = [COLORS['ESP'], COLORS['SWE'], COLORS['GBR']]
    bars       = ax.bar(x, vals, color=bar_colors, width=WIDTH,
                        edgecolor='white', linewidth=0.8)

    # Zero line
    ax.axhline(0, color='#333333', linewidth=0.75, zorder=0)

    # Axes formatting
    ax.set_xticks(x)
    ax.set_xticklabels(['ESP', 'SWE', 'GBR'], fontsize=10.5)
    ax.set_title(title, fontsize=9.5, fontweight='bold', pad=7, ha='center')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(axis='y', labelsize=9)

    # Value labels above / below each bar
    v_range = max(abs(v) for v in vals) if any(v != 0 for v in vals) else 1
    offset  = 0.05 * v_range
    for bar, val in zip(bars, vals):
        fmt = f'{val:.1f}' if abs(val) >= 1 else f'{val:.3f}'
        if val >= 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    val + offset, fmt,
                    ha='center', va='bottom', fontsize=8.5, fontweight='bold')
        else:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    val - offset, fmt,
                    ha='center', va='top', fontsize=8.5, fontweight='bold')

# ── 5. Legend and footnote ────────────────────────────────────────────────────
patches = [mpatches.Patch(color=COLORS[c], label=C_LEGEND[c])
           for c in ['ESP', 'SWE', 'GBR']]
fig.legend(handles=patches, loc='lower center', ncol=3,
           fontsize=10, bbox_to_anchor=(0.5, -0.05), frameon=False)

fig.text(
    0.01, -0.10,
    '\u2020 Sweden: JST Macrohistory Database R6 records banking crisis onset 2008 '
    '(target_h2\u202f=\u202f1 in 2007). Crisis mechanism: contagion from '
    'international markets, not domestic credit boom.',
    fontsize=8.5, color='#555555', style='italic'
)

# ── 6. Caption as suptitle ────────────────────────────────────────────────────
fig.suptitle(
    'Figure 5.1.  Key macro-financial features for Spain (correct hit), '
    'Sweden (true positive) and UK (false negative), 2004\u20132006 averages.\n'
    'Panels 1 and 3: raw annual percentages. '
    'Panels 2, 4 and 5: demeaned deviations from expanding country-specific means. '
    'Source: JST Macrohistory Database R6.',
    fontsize=9.5, y=1.05, ha='center'
)

plt.tight_layout()

# ── 7. Save ───────────────────────────────────────────────────────────────────
os.makedirs("figures", exist_ok=True)
OUT = os.path.join("figures", "figure_5_1_case_study_features.png")
plt.savefig(OUT, dpi=200, bbox_inches='tight', facecolor='white')
print(f"\nFigure saved to:  {OUT}")
print("Insert into Discussion_Chapter5_v5.docx between Table 5.1 and Section 5.4.1.")
