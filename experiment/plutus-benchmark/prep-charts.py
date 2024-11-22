# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: light
#       format_version: '1.5'
#       jupytext_version: 1.16.4
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# # Notebook format
#
# This is a Jupyter Notebook that has been converted to pure Python using Jupytext for easier version control.
#
# It can be converted back to the ipynb format using the following command:
# ```
# jupytext --to ipynb prep-results.py
# ```

# +
import pandas as pd
import os
import re

base_dir = '/workspace/experiment/plutus-benchmark'
data_dir = base_dir + '/20241119'

def load_data(dir_path):
    recs = []
    for fname in os.listdir(dir_path):
        m = re.match("^([^\\-]+)-(\\d+).csv$", fname)
        if m:
            print(fname)
            df = pd.read_csv(dir_path + "/" + fname)
            recs.append({
                "name": m.group(1),
                "threads": int(m.group(2)),
                "rate": 1 / df["run_time"].mean()
            })
    return pd.DataFrame.from_records(recs)

df = load_data(data_dir)
df.head()
# -


# ## Plutus witness validation rate

# +
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

sns.set_palette(['#2CA02C'], n_colors=100)
g = sns.barplot(data=df, y='rate', x='threads', hue='name')
g.set(ylabel='rate, scripts per worker per second', xlabel='number of worker threads')
plt.legend()
fig = g.get_figure()
fig.savefig(data_dir + '/chart-rate.png', dpi=300)
plt.show(g)
# -
# ## Parallel efficiency

base_rate = df.loc[df['threads'] == 1]['rate']
df['efficiency'] = df['rate'] * 100 / base_rate[0]
g = sns.barplot(data=df, y='efficiency', x='threads',  hue='name', saturation=1.0)
g.set(ylabel='parallel efficiency, %', xlabel='number of worker threads')
ax = g.axes
ax.axhline(90, ls='--', color='b', label='90% level')
plt.legend()
fig = g.get_figure()
fig.savefig(data_dir + '/chart-efficiency.png', dpi=300)
plt.show(g)

# # Predicted time to validate all Plutus witnesses

# +
# this count is produced by txwit-stat command
total_redeemers = 40_525_056

df['pred_time'] = round(total_redeemers / (df['rate'] * df['threads']) / 60, 1)
g = sns.barplot(data=df, y='pred_time', x='threads',  hue='name', saturation=1.0)
g.set(ylabel='predicted time, min', xlabel='number of worker threads')
for c in g.containers:
    g.bar_label(c)
plt.legend()
fig = g.get_figure()
fig.savefig(data_dir + '/chart-predicted-time.png', dpi=300)
plt.show(g)
