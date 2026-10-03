#!/usr/bin/env python3
"""Recompute metrics from exported decisions without issuing any model calls."""
import argparse
import csv
import io
import json
import zipfile
from collections import defaultdict
from pathlib import Path

METRICS = ['vulnerability_detected', 'cwe_correct', 'function_correct', 'line_correct', 'statement_correct', 'full_correct']


def emit(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in data for k in r)))
        w.writeheader()
        w.writerows(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evaluation', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    groups = defaultdict(dict)
    training = []
    with zipfile.ZipFile(args.evaluation) as z:
        for name in z.namelist():
            parts = name.split('/')
            if name.startswith('test/scores/') and name.endswith('/verdict.json') and len(parts) == 7:
                _, _, model, skill, variant, case, _ = parts
                d = json.loads(z.read(name))
                if not all(type(d.get(m)) is bool for m in METRICS):
                    continue
                if d['full_correct'] and not all(d[m] for m in METRICS[:-1]):
                    raise ValueError(f'inconsistent full_correct: {name}')
                groups[(model, skill, variant)][case] = d
            elif name.startswith('train/analysis/results/') and name.endswith('.jsonl'):
                for line in z.read(name).splitlines():
                    if not line.strip():
                        continue
                    d = json.loads(line)
                    if 'task_id' in d and 'cwe_match' in d:
                        training.append(d)
    per_case = []
    summaries = []
    for (model, skill, variant), outcomes in sorted(groups.items()):
        row = dict(model_class=model, skill=skill, variant=variant, scored=len(outcomes), expected=100)
        for metric in METRICS:
            n = sum(d[metric] for d in outcomes.values())
            row[metric + '_count'] = n
            row[metric + '_accuracy_scored'] = n / len(outcomes)
        summaries.append(row)
        for case, d in sorted(outcomes.items()):
            per_case.append(dict(model_class=model, skill=skill, variant=variant, case_id=case, **{m: d[m] for m in METRICS}))
    paired = []
    for model, skill, variant in sorted(groups):
        if variant not in ['baseline', 'original']:
            continue
        a = groups[(model, skill, variant)]
        b = groups.get((model, skill, 'refined'), {})
        cases = sorted(a.keys() & b.keys())
        if not cases:
            continue
        for metric in METRICS:
            ac = sum(a[c][metric] for c in cases)
            bc = sum(b[c][metric] for c in cases)
            paired.append(dict(model_class=model, skill=skill, metric=metric, paired_cases=len(cases), baseline_correct=ac,
                               refined_correct=bc, improvement_percentage_points=100 * (bc - ac) / len(cases),
                               relative_improvement=(bc - ac) / ac if ac else 'undefined_zero_baseline',
                               gained=sum(not a[c][metric] and b[c][metric] for c in cases),
                               lost=sum(a[c][metric] and not b[c][metric] for c in cases)))
    unique = {}
    for d in training:
        if d['task_id'] in unique and unique[d['task_id']] != d:
            raise ValueError('conflicting evaluator decisions: ' + d['task_id'])
        unique[d['task_id']] = d
    train_rows = []
    train_groups = defaultdict(list)
    for d in unique.values():
        train_rows.append({k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in d.items()})
        train_groups[(d.get('source_model', ''), d.get('skill_name', ''))].append(d)
    train_summary = []
    for (model, skill), data in sorted(train_groups.items()):
        row = dict(source_model=model, skill=skill, scored=len(data))
        for field in ['vulnerability_detected', 'cwe_match', 'correct_functions_identified', 'correct_lines_or_statements_identified']:
            row[field + '_count'] = sum(d.get(field) is True for d in data)
            row[field + '_accuracy_scored'] = row[field + '_count'] / len(data)
        train_summary.append(row)
    emit(args.output / 'test_per_case.csv', per_case)
    emit(args.output / 'test_metrics.csv', summaries)
    emit(args.output / 'test_paired_improvements.csv', paired)
    emit(args.output / 'training_analysis.csv', train_rows)
    emit(args.output / 'training_metrics.csv', train_summary)
    print(f'{len(per_case)} held-out judgments; {len(unique)} training judgments; {len(paired)} paired comparisons')


if __name__ == '__main__':
    main()
