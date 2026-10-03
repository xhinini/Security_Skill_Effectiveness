#!/usr/bin/env python3
"""Build a shared run index pointing to native reports and trajectories."""
import argparse
import csv
import json
import re
import zipfile
from collections import defaultdict
from pathlib import Path


def csv_rows(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))


def runtime(metadata):
    value = metadata.get('agent_runtime', metadata.get('runtime'))
    if value:
        return value
    if 'claude_settings' in metadata:
        return 'claude-code'
    return None


def make_record(archive, names, metadata, record_id, phase, split, skill, case,
                model_class=None, variant=None, round_id=None, status=None,
                metadata_member=None):
    def ref(name):
        return archive + '::' + name

    reports, trajectories, prompts = [], [], []
    for name in names:
        parts = name.split('/')
        leaf = parts[-1]
        if any(p in {'_attempts', 'prior_failed_high'} for p in parts):
            continue
        if 'trajectory' in leaf:
            trajectories.append(ref(name))
        elif leaf == 'prompt.txt':
            prompts.append(ref(name))
        elif leaf in {'final.json', 'final.txt', 'response.txt', 'result.json', 'stdout.txt'} or 'artifacts' in parts:
            reports.append(ref(name))
    return {
        'schema': 'study-run/1', 'record_id': record_id,
        'phase': phase, 'split': split, 'model_class': model_class,
        'skill': skill, 'case_id': case, 'variant': variant, 'round': round_id,
        'status': metadata.get('status', status or 'not_recorded'),
        'reproduction_interface': 'claude-code-cli',
        'reports': sorted(reports), 'trajectories': sorted(trajectories),
        'prompts': sorted(prompts),
        'provenance': {
            'execution_runtime': runtime(metadata),
            'model': metadata.get('model'), 'effort': metadata.get('effort'),
            'metadata_ref': ref(metadata_member) if metadata_member else None,
        },
    }


def build(package):
    core = package / 'core'
    output = core / 'indexes/runs.jsonl'
    records = []
    plans = defaultdict(list)
    for path in sorted((core / 'indexes').glob('training-*.csv')):
        for row in csv_rows(path):
            row.update(phase='training', split='train', variant='original')
            plans[row['archive']].append(row)
    for row in csv_rows(core / 'indexes/testing.csv'):
        row.update(phase='testing', split='test')
        plans[row['archive']].append(row)
    for archive, rows in sorted(plans.items()):
        with zipfile.ZipFile(package / archive) as z:
            by_prefix = defaultdict(list)
            for name in z.namelist():
                match = re.search(r'/case_\d{3}/', name)
                if match:
                    by_prefix[name[:match.end() - 1]].append(name)
            for row in rows:
                names = by_prefix[row['prefix']]
                member = row['prefix'] + '/run.json'
                metadata = json.loads(z.read(member)) if member in names else {}
                identity = '/'.join(row[k] for k in ['phase', 'model_class', 'variant', 'skill', 'case_id'])
                records.append(make_record(archive, names, metadata, identity, row['phase'], row['split'],
                                           row['skill'], row['case_id'], model_class=row['model_class'],
                                           variant=row['variant'], status=row['status'],
                                           metadata_member=member if member in names else None))
    archive = 'refinement.zip'
    with zipfile.ZipFile(package / archive) as z:
        by_prefix = defaultdict(list)
        for name in z.namelist():
            match = re.match(r'([^/]+)/(round_\d+)/records/[^/]+/train/detector/(case_\d{3})/', name)
            if match:
                by_prefix[(match[1], match[2], match[3], name[:match.end()])].append(name)
        for (skill, round_id, case, prefix), names in sorted(by_prefix.items()):
            member = prefix + 'run.json'
            metadata = json.loads(z.read(member)) if member in names else {}
            records.append(make_record(archive, names, metadata, f'refinement/{skill}/{round_id}/{case}',
                                       'refinement', 'train', skill, case, round_id=round_id,
                                       metadata_member=member if member in names else None))
    identifiers = [r['record_id'] for r in records]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError('duplicate run identifiers')
    temporary = output.with_suffix('.partial')
    with temporary.open('w') as f:
        for record in sorted(records, key=lambda r: r['record_id']):
            f.write(json.dumps(record, separators=(',', ':')) + '\n')
    temporary.replace(output)
    schema = {
        'schema': 'study-run/1',
        'reference_format': 'archive.zip::member/path',
        'fields': {
            'record_id': 'Unique phase/model/variant/skill/case or refinement/skill/round/case identifier.',
            'status': 'Recorded execution status; pending cells have empty artifact references.',
            'reproduction_interface': 'Interface provided by run.py for reproducing detector runs.',
            'reports': 'Native final responses, stdout and collected report artifacts.',
            'trajectories': 'Native saved execution streams.',
            'provenance': 'Observed execution runtime, model, effort and metadata reference; null means unrecorded.',
        },
    }
    (core / 'indexes/run_schema.json').write_text(json.dumps(schema, indent=2) + '\n')
    print(f'Indexed {len(records)} runs using study-run/1')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    build(parser.parse_args().package)
