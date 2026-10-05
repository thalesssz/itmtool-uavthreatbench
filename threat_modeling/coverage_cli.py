"""
Command-line entry for CoverageService: reference coverage across threat sources.

Example (inside the container, with the data folder mounted at /data):

    python -m threat_modeling.coverage_cli \\
        --scenarios /data/plausible_uav_ot_cyber_scenarios_withThreats.json \\
        --scenario-id CS-OT-UAV-0287 \\
        --tm7 /data/CS-OT-UAV-0287-DFD-LLM.tm7 \\
        --source "LLM (ITA TMT)=/data/threat_analysis_qwen2.5_7b.json" \\
        --source "LLM (conversational)=/data/threats-conversational.txt" \\
        --provider OLLAMA --model qwen2.5:7b \\
        --out /data/coverage-0287

Threat files: .txt (one threat per line), .csv/.tsv or .json (records with a
description/Description/Threat field, or an object holding such a list).
"""
import argparse
import csv
import io
import json
import os

from .services.coverage_service import CoverageService, DEFAULT_THRESHOLD
from .services.threat_model_service import ThreatModelService


DESCRIPTION_KEYS = ('description', 'Description', 'Threat', 'threat')
LIST_KEYS = ('threat_model', 'threats', 'Expected Threats', 'results')


def load_scenario(path: str, scenario_id: str):
    """Return (expected threat texts, scenario description) from a UAVThreatBench-style JSON."""
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)

    scenario = next((s for s in data if s.get('Scenario ID') == scenario_id), None)
    if scenario is None:
        raise SystemExit(f"Scenario {scenario_id} not found in {path}")

    expected = [t['Threat'] for t in scenario.get('Expected Threats', []) if t.get('Threat')]
    return expected, scenario.get('Scenario Description', '')


def load_tm7_threats(path: str, diagram_index: int):
    """Return the threat descriptions saved in a .tm7 for one diagram."""
    with open(path, encoding='utf-8-sig') as handle:
        threat_model = ThreatModelService.parse_tm7_file(handle.read())

    threats = ThreatModelService.get_diagram_threats(threat_model, diagram_index)
    return [t.description for t in threats if t.description]


def _record_text(record):
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        for key in DESCRIPTION_KEYS:
            if record.get(key):
                return str(record[key])
    return ''


def load_threat_file(path: str):
    """Return threat texts from a .txt, .csv/.tsv or .json file."""
    extension = os.path.splitext(path)[1].lower()

    with open(path, encoding='utf-8-sig') as handle:
        content = handle.read()

    if extension == '.txt':
        return [line.strip() for line in content.splitlines() if line.strip()]

    if extension in ('.csv', '.tsv'):
        header = content.split('\n', 1)[0]
        delimiter = '\t' if header.count('\t') > header.count(',') else ','
        records = list(csv.DictReader(io.StringIO(content), delimiter=delimiter))
    else:
        records = json.loads(content)
        if isinstance(records, dict):
            records = next((records[k] for k in LIST_KEYS if isinstance(records.get(k), list)), None)
            if records is None:
                raise SystemExit(f"No threat list found in {path}")

    return [text for text in (_record_text(r) for r in records) if text]


def parse_source(value: str):
    """Parse NAME=PATH."""
    if '=' not in value:
        raise argparse.ArgumentTypeError('use NAME=PATH')
    name, path = value.split('=', 1)
    return name.strip(), path.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--scenarios', required=True, help='Scenario JSON with "Expected Threats"')
    parser.add_argument('--scenario-id', required=True)
    parser.add_argument('--tm7', help='.tm7 file whose saved threats are one source')
    parser.add_argument('--tm7-name', default='MTMT', help='Source name for the .tm7 threats')
    parser.add_argument('--diagram', type=int, default=0, help='Diagram index in the .tm7')
    parser.add_argument('--source', action='append', default=[], type=parse_source,
                        help='Extra source as NAME=PATH (repeatable)')
    parser.add_argument('--provider', default='OLLAMA')
    parser.add_argument('--model', required=True, help='Judge model')
    parser.add_argument('--api-key', default=None)
    parser.add_argument('--threshold', type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument('--no-context', action='store_true', help='Do not show the scenario description to the judge')
    parser.add_argument('--fresh', action='store_true', help='Judge everything again instead of reusing remembered judgments')
    parser.add_argument('--out', required=True, help='Output prefix for the CSV files')
    args = parser.parse_args()

    expected, context = load_scenario(args.scenarios, args.scenario_id)

    sources = {}
    if args.tm7:
        sources[args.tm7_name] = load_tm7_threats(args.tm7, args.diagram)
    for name, path in args.source:
        sources[name] = load_threat_file(path)
    if not sources:
        raise SystemExit('Give at least one source (--tm7 or --source)')

    print(f"Scenario {args.scenario_id}: {len(expected)} expected threats")
    for name, texts in sources.items():
        print(f"  {name}: {len(texts)} threats, {len(set(t.strip() for t in texts))} distinct")

    service = CoverageService()
    pairs_df, coverage_df = service.run_coverage(
        expected_threats=expected,
        sources=sources,
        provider=args.provider,
        model_name=args.model,
        api_key=args.api_key,
        server_ip=None,
        scenario_context='' if args.no_context else context,
        threshold=args.threshold,
        verbose=False,
        use_cache=not args.fresh
    )
    stats = service.last_stats
    print(f"\n{stats['total']} judgments: {stats['judged']} judged now, {stats['reused']} from memory, "
          f"{stats['failed']} failed, {stats['seconds']} s"
          + (f", US$ {stats['cost']:.4f}" if stats.get('cost') is not None else ''))
    if stats['failed']:
        print("WARNING: failed judgments count as score 0. Run again to retry only them.")
    summary_df = CoverageService.summarize(pairs_df, coverage_df, args.threshold)

    pairs_df.to_csv(f"{args.out}-pairs.csv", index=False, sep='\t')
    coverage_df.to_csv(f"{args.out}-coverage.csv", index=False, sep='\t')
    summary_df.to_csv(f"{args.out}-summary.csv", index=False, sep='\t')

    print(f"\nBest score per expected threat (covered = score >= {args.threshold}):")
    names = list(sources)
    print('     ' + ''.join(f"{n[:22]:>24}" for n in names))
    for index, text in enumerate(expected, start=1):
        cells = []
        for name in names:
            row = coverage_df[(coverage_df['expected_index'] == index) & (coverage_df['source'] == name)].iloc[0]
            cells.append(f"{row['best_score']:.2f} {'OK' if row['covered'] else '--'}")
        print(f"  T{index} " + ''.join(f"{c:>24}" for c in cells) + f"   {text[:60]}")

    print('\n' + summary_df.to_string(index=False))
    print(f"\nFiles: {args.out}-pairs.csv, {args.out}-coverage.csv, {args.out}-summary.csv")


if __name__ == '__main__':
    main()
