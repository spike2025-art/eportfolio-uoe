"""
Case Study Figures — Section 5.4.1
Figures 5.1a, 5.1b and Table 5.1

Spain / Sweden / United Kingdom — 2004-2006 macro-financial feature comparison

Run from anywhere — uses absolute paths throughout.
Conda env: dissertation

Outputs:
    C:\Users\Owner\OneDrive\dissertation\figures\figure_5_1a_credit_housing.png
    C:\Users\Owner\OneDrive\dissertation\figures\figure_5_1b_monetary_yield.png
    C:\Users\Owner\OneDrive\dissertation\figures\table_5_1_case_study_summary.png
"""

import pandas as pd, numpy as np, matplotlib.pyplot as plt, os

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE    = r"C:\Users\Owner\OneDrive\dissertation"
DATA    = os.path.join(BASE, r"data\processed\augmented_analysis\df_macro_augmented.csv")
FIG_DIR = os.path.join(BASE, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

# ── Load data ─────────────────────────────────────────────────────────────────
df  = pd.read_csv(DATA)
sub = df[df['iso'].isin(['ESP','SWE','GBR']) & df['year'].isin([2004,2005,2006])]
print(f"Rows loaded: {len(sub)} (expected 9 = 3 countries x 3 years)")

# ── Shared constants ──────────────────────────────────────────────────────────
ISOS   = ['ESP',         'SWE',                    'GBR']
NAMES  = ['Spain',       'Sweden',                 'United Kingdom']
ROLES  = ['Correct hit', 'True positive\u2020',    'Qualitative\nscope failure']
COLORS = ['#2166ac',     '#4dac26',                '#d01c8b']
PROBS  = ['0.810',       '0.783',                  '0.171']
X, W   = np.arange(3), 0.52


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 5.1a — Credit & Housing Conditions
# ══════════════════════════════════════════════════════════════════════════════
vals_a = {c: {
    'credit_raw': sub[sub['iso']==c]['tloans_gr_lag1'].mean() * 100,
    'hp_raw':     sub[sub['iso']==c]['hpnom_gr_lag1'].mean() * 100,
} for c in ISOS}

def bar_panel_a(ax, key, title, ylabel):
    data = [vals_a[c][key] for c in ISOS]
    bars = ax.bar(X, data, width=W, color=COLORS,
                  edgecolor='white', linewidth=1.0, zorder=3)
    ax.axhline(0, color='#555555', linewidth=0.8, zorder=2)
    ax.set_title(title, fontsize=12, fontweight='bold', pad=10, color='#222222')
    ax.set_ylabel(ylabel, fontsize=10, color='#555555')
    ax.spines[['top','right']].set_visible(False)
    ax.spines[['left','bottom']].set_color('#cccccc')
    ax.yaxis.grid(True, color='#eeeeee', linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.set_ylim(0, max(data) * 1.45)  # headroom for 3-line tick labels

    ax.set_xticks(X)
    ax.set_xticklabels(
        [f'{n}\n{r}' for n, r in zip(NAMES, ROLES)],
        fontsize=9, linespacing=1.6
    )
    for tick, col in zip(ax.get_xticklabels(), COLORS):
        tick.set_color(col)

    vr = max(abs(v) for v in data) or 1
    for bar, v in zip(bars, data):
        ax.text(bar.get_x() + bar.get_width()/2, v + 0.03*vr,
                f'{v:.1f}', ha='center', va='bottom',
                fontsize=11.5, fontweight='bold', color='#111111')

    box_lines = ['E1-EBM probabilities'] + [f'{n}: {p}' for n, p in zip(NAMES, PROBS)]
    ax.text(0.97, 0.97, '\n'.join(box_lines), transform=ax.transAxes,
            ha='right', va='top', fontsize=8.5, color='#333333', linespacing=1.7,
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#f9f9f9',
                      edgecolor='#888888', linestyle='dashed', linewidth=0.9, alpha=0.9))

fig1, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 7.5))
fig1.patch.set_facecolor('white')
fig1.subplots_adjust(wspace=0.38, bottom=0.26, top=0.88)

bar_panel_a(ax1, 'credit_raw', 'Credit growth\n(raw, % p.a.)',      'Annual growth (%)')
bar_panel_a(ax2, 'hp_raw',     'House price growth\n(raw, % p.a.)', 'Annual growth (%)')

fig1.suptitle(
    'Figure 5.1a.  Credit and housing conditions \u2014 Spain / Sweden / UK, 2004\u20132006 averages',
    fontsize=12.5, fontweight='bold', y=0.98
)
fig1.text(
    0.5, 0.01,
    'Raw annual percentage growth (lag 1). Source: JST Macrohistory Database R6.',
    ha='center', fontsize=9, color='#666666'
)

OUT_A = os.path.join(FIG_DIR, 'figure_5_1a_credit_housing.png')
fig1.savefig(OUT_A, dpi=200, bbox_inches='tight', facecolor='white')
plt.show()
print(f"Saved \u2192 {OUT_A}")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 5.1b — Monetary & Yield-Curve Conditions
# ══════════════════════════════════════════════════════════════════════════════
vals_b = {c: {
    'ts_dm':   sub[sub['iso']==c]['term_spread_lag1_dm'].mean(),
    'stir_dm': sub[sub['iso']==c]['stir_lag1_dm'].mean(),
} for c in ISOS}

def bar_panel_b(ax, key, title, ylabel, fmt='.3f', box_x=0.97, box_y=0.97, box_va='top'):
    data = [vals_b[c][key] for c in ISOS]
    bars = ax.bar(X, data, width=W, color=COLORS,
                  edgecolor='white', linewidth=1.0, zorder=3)
    ax.axhline(0, color='#555555', linewidth=0.8, zorder=2)
    ax.set_title(title, fontsize=11, fontweight='bold', pad=10, color='#222222')
    ax.set_ylabel(ylabel, fontsize=10, color='#555555')
    ax.spines[['top','right']].set_visible(False)
    ax.spines[['left','bottom']].set_color('#cccccc')
    ax.yaxis.grid(True, color='#eeeeee', linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)

    vr      = max(abs(v) for v in data) or 1
    all_neg = all(v <= 0 for v in data)
    all_pos = all(v >= 0 for v in data)
    if all_pos:   ax.set_ylim(0, max(data) * 1.55)  # headroom for 3-line labels
    elif all_neg: ax.set_ylim(min(data) * 1.28, max(data) + vr * 0.45)
    else:         ax.set_ylim(min(data) * 1.38, max(data) * 1.38)

    ax.set_xticks(X)
    ax.set_xticklabels(
        [f'{n}\n{r}' for n, r in zip(NAMES, ROLES)],
        fontsize=9, linespacing=1.6
    )
    for tick, col in zip(ax.get_xticklabels(), COLORS):
        tick.set_color(col)

    for bar, v in zip(bars, data):
        offset = 0.03*vr if v >= 0 else -0.03*vr
        ax.text(bar.get_x() + bar.get_width()/2, v + offset, f'{v:{fmt}}',
                ha='center', va='bottom' if v >= 0 else 'top',
                fontsize=11, fontweight='bold', color='#111111')

    box_lines = ['E1-EBM probabilities'] + [f'{n}: {p}' for n, p in zip(NAMES, PROBS)]
    ax.text(box_x, box_y, '\n'.join(box_lines), transform=ax.transAxes,
            ha='right', va=box_va, fontsize=8.5, color='#333333', linespacing=1.7,
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#f9f9f9',
                      edgecolor='#888888', linestyle='dashed', linewidth=0.9, alpha=0.9))

fig2, (ax3, ax4) = plt.subplots(1, 2, figsize=(13, 7.5))
fig2.patch.set_facecolor('white')
fig2.subplots_adjust(wspace=0.40, bottom=0.26, top=0.82)

bar_panel_b(ax3, 'ts_dm',
            'Term spread lag 1 (demeaned, pp)',
            'Deviation from country mean (pp)',
            fmt='.3f', box_x=0.97, box_y=0.97, box_va='top')

bar_panel_b(ax4, 'stir_dm',
            'Short-term rate lag 1 (demeaned, pp)',
            'Deviation from country mean (pp)',
            fmt='.2f', box_x=0.97, box_y=0.05, box_va='bottom')

fig2.suptitle(
    'Figure 5.1b.  Monetary and yield-curve conditions\n'
    'Spain / Sweden / United Kingdom \u2014 2004\u20132006 averages',
    fontsize=13, fontweight='bold', y=0.97
)
fig2.text(
    0.5, 0.01,
    'Source: JST Macrohistory Database R6.  '
    '\u2020 Sweden: crisis onset 2008 (target_h2\u202f=\u202f1 in 2007); '
    'contagion mechanism \u2014 true positive.',
    ha='center', fontsize=8.5, color='#777777', style='italic'
)

OUT_B = os.path.join(FIG_DIR, 'figure_5_1b_monetary_yield.png')
fig2.savefig(OUT_B, dpi=200, bbox_inches='tight', facecolor='white')
plt.show()
print(f"Saved \u2192 {OUT_B}")


# ══════════════════════════════════════════════════════════════════════════════
# TABLE 5.1 — Case Study Feature Evidence
# ══════════════════════════════════════════════════════════════════════════════
col_headers = ['Feature', 'Spain', 'Sweden', 'United Kingdom']
rows = [
    ['Role',                         'Correct hit',  'True positive\u2020', 'Qualitative scope failure'],
    ['E1-EBM probability',           '0.810',        '0.783',               '0.171'],
    ['Credit growth, raw (% p.a.)',  '19.8',         '7.4',                 '9.3'],
    ['House price growth (% p.a.)',  '17.6',         '11.1',                '13.3'],
    ['Term spread lag 1 (dem., pp)', '1.280',        '1.069',               '0.538'],
    ['Short rate lag 1 (dem., pp)',  '\u22126.77',   '\u22125.60',          '\u22123.57'],
]
note = (
    'Averages over 2004\u20132006, lag 1.  '
    'Demeaned\u202f=\u202fdeviation from expanding country-specific historical mean.\n'
    '\u2020 Sweden: JST R6 records crisis onset 2008 (target_h2\u202f=\u202f1 in 2007); '
    'mechanism is contagion, not domestic credit boom.\n'
    'Source: JST Macrohistory Database R6; NB09B ensemble output.'
)

fig3, ax = plt.subplots(figsize=(12, 4.4))
fig3.patch.set_facecolor('white')
ax.axis('off')

tbl = ax.table(cellText=rows, colLabels=col_headers, cellLoc='center', loc='center')
tbl.auto_set_font_size(False)
tbl.set_fontsize(10)
tbl.scale(1, 1.9)

# Header row
for col_idx, color in enumerate(['#333333'] + COLORS):
    cell = tbl[0, col_idx]
    cell.set_facecolor('#222222' if col_idx == 0 else color)
    cell.set_text_props(color='white', fontweight='bold', fontsize=10.5)
    cell.set_edgecolor('white')

# Data rows
for row_idx in range(1, len(rows) + 1):
    bg = '#f5f5f5' if row_idx % 2 == 0 else 'white'
    for col_idx in range(4):
        cell = tbl[row_idx, col_idx]
        cell.set_facecolor(bg)
        cell.set_edgecolor('#dddddd')
        if col_idx > 0:
            cell.set_text_props(color=COLORS[col_idx - 1], fontweight='bold')
        else:
            cell.set_text_props(color='#333333', fontweight='normal')

ax.set_title(
    'Table 5.1.  Case study feature evidence \u2014 Spain, Sweden, and the United Kingdom',
    fontsize=12, fontweight='bold', pad=14, loc='left', color='#222222'
)
fig3.text(0.01, -0.10, note, fontsize=8, color='#555555', style='italic', linespacing=1.6)

OUT_T = os.path.join(FIG_DIR, 'table_5_1_case_study_summary.png')
fig3.savefig(OUT_T, dpi=200, bbox_inches='tight', facecolor='white')
plt.show()
print(f"Saved \u2192 {OUT_T}")

print("\nAll outputs saved to:")
print(f"  {OUT_A}")
print(f"  {OUT_B}")
print(f"  {OUT_T}")
