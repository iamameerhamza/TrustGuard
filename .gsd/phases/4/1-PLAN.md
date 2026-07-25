---
phase: 4
plan: 1
wave: 1
---

# Plan 4.1: Dataset Collection Pipeline

## Objective
Build a repeatable pipeline collecting from Tranco, OpenPhish, and URLHaus.

## Context
- .gsd/ROADMAP.md
- app/core/extractor.py

## Tasks

<task type="auto">
  <name>Dataset Pipeline Script</name>
  <files>scripts/dataset_builder.py, data/.gitignore</files>
  <action>
    - Create `data/` directory to store CSVs.
    - Create `scripts/dataset_builder.py` to fetch, sample (5000 safe, 5000 phishing), extract features, and save to `data/dataset.csv`.
  </action>
  <verify>python scripts/dataset_builder.py</verify>
  <done>Pipeline successfully builds dataset.csv without errors.</done>
</task>
