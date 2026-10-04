"""Coverage Service - How much of a reference threat list each threat source covers."""
import pandas as pd
from typing import Dict, List, Optional, Tuple

from ..api.llm_client import LLMClient
from ..api.message_builder import generate_coverage_messages
from ..models.comparison_models import ThreatComparisonResponse


DEFAULT_THRESHOLD = 0.7


class CoverageService:
    """
    Service for measuring reference coverage across threat sources.

    ComparisonService pairs TMT and AI threats by (dataflow, category), which only
    works when both sides come from the same .tm7. Reference threats (e.g. the
    expected threats of a benchmark scenario) have no dataflow, and another LLM
    pipeline may name elements its own way. Here every reference threat is judged
    against every threat of every source, and a reference threat counts as covered
    by a source when the best score reaches the threshold.
    """

    def __init__(self):
        """Initialize the coverage service."""
        pass

    def run_coverage(self, expected_threats: List[str], sources: Dict[str, List[str]],
                     provider: str, model_name: str, api_key: Optional[str] = None,
                     server_ip: Optional[str] = None, scenario_context: str = "",
                     threshold: float = DEFAULT_THRESHOLD,
                     verbose: bool = False) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Judge every reference threat against every threat of every source.

        Args:
            expected_threats: Reference threat texts
            sources: Source name -> list of threat texts
            provider: LLM provider name
            model_name: Model name to use as judge
            api_key: API key (optional)
            server_ip: Server IP for Ollama (optional)
            scenario_context: Scenario description shown to the judge (optional)
            threshold: Minimum score for a reference threat to count as covered
            verbose: Print progress

        Returns:
            Tuple (pairs_df, coverage_df):
            - pairs_df: one row per (reference threat, source, distinct candidate text)
              with similarity_score, is_similar and explanation
            - coverage_df: one row per (reference threat, source) with best_score,
              covered, matches_at_threshold and the best candidate
        """
        llm_client = LLMClient(
            provider=provider,
            model_name=model_name,
            api_key=api_key,
            server_ip=server_ip
        )

        pair_rows = []
        coverage_rows = []

        for expected_index, expected in enumerate(expected_threats, start=1):
            for source, candidates in sources.items():
                # Identical texts get identical scores, so each distinct text is judged once.
                distinct = list(dict.fromkeys(c.strip() for c in candidates if c and c.strip()))
                source_rows = []

                for candidate_index, candidate in enumerate(distinct, start=1):
                    try:
                        messages = generate_coverage_messages(expected, candidate, scenario_context)
                        response = llm_client.invoke_with_structure(messages, ThreatComparisonResponse)
                        score = response.similarity_score
                        is_similar = response.is_similar
                        explanation = response.explanation
                    except Exception as e:
                        print(f"Error judging coverage: {str(e)}")
                        score, is_similar = 0.0, False
                        explanation = f'Error during coverage judgment: {str(e)}'

                    row = {
                        'expected_index': expected_index,
                        'expected_threat': expected,
                        'source': source,
                        'candidate_index': candidate_index,
                        'candidate_threat': candidate,
                        'similarity_score': score,
                        'is_similar': is_similar,
                        'explanation': explanation
                    }
                    source_rows.append(row)

                    if verbose:
                        print(f"  T{expected_index} x {source} #{candidate_index}/{len(distinct)}: {score:.2f}")

                pair_rows.extend(source_rows)

                # "covered" follows the score, not the judge's boolean, so one
                # threshold rules every source even if the judge is inconsistent.
                best = max(source_rows, key=lambda r: r['similarity_score'], default=None)
                coverage_rows.append({
                    'expected_index': expected_index,
                    'expected_threat': expected,
                    'source': source,
                    'candidates': len(distinct),
                    'best_score': best['similarity_score'] if best else 0.0,
                    'covered': bool(best and best['similarity_score'] >= threshold),
                    'matches_at_threshold': sum(1 for r in source_rows if r['similarity_score'] >= threshold),
                    'best_candidate': best['candidate_threat'] if best else '',
                    'best_explanation': best['explanation'] if best else ''
                })

        return pd.DataFrame(pair_rows), pd.DataFrame(coverage_rows)

    @staticmethod
    def _max_assignment(pairs: pd.DataFrame, threshold: float) -> set:
        """
        Reference threats covered when each candidate may cover at most one of them.

        Maximum bipartite matching (augmenting paths) between reference threats and
        candidate threats, over the pairs whose score reaches the threshold.

        Returns:
            Set of covered reference indexes
        """
        if pairs.empty:
            return set()
        ok = pairs[pairs['similarity_score'] >= threshold]
        options = {}
        for _, row in ok.sort_values(['expected_index', 'similarity_score'], ascending=[True, False]).iterrows():
            options.setdefault(int(row['expected_index']), []).append(row['candidate_threat'])
        owner = {}  # candidate -> reference index it currently covers

        def assign(ref, seen):
            for cand in options.get(ref, []):
                if cand in seen:
                    continue
                seen.add(cand)
                if cand not in owner or assign(owner[cand], seen):
                    owner[cand] = ref
                    return True
            return False

        for ref in sorted(options):
            assign(ref, set())
        return set(owner.values())

    @staticmethod
    def summarize(pairs_df: pd.DataFrame, coverage_df: pd.DataFrame,
                  threshold: float = DEFAULT_THRESHOLD) -> pd.DataFrame:
        """
        Summarize coverage per source.

        Args:
            pairs_df: Pairs DataFrame returned by run_coverage
            coverage_df: Coverage DataFrame returned by run_coverage
            threshold: Same threshold used in run_coverage

        Returns:
            DataFrame with one row per source: reference threats covered (best
            match per reference threat), covered under unique assignment (each
            candidate credited at most once), total, distinct candidates and how
            many candidates match any reference threat
        """
        rows = []

        for source in coverage_df['source'].unique():
            coverage = coverage_df[coverage_df['source'] == source]
            pairs = pairs_df[pairs_df['source'] == source] if not pairs_df.empty else pairs_df
            matching = pairs[pairs['similarity_score'] >= threshold]['candidate_threat'].nunique() if not pairs.empty else 0

            # One threat covering two different reference threats inflates the
            # score and rewards generic wording: a single "data may be sniffed"
            # threat could be credited for every confidentiality expectation.
            # Under unique assignment each candidate is credited at most once.
            # This is a maximum bipartite matching; a greedy pass by score is
            # not enough, because the result then depends on how ties are
            # ordered (a reference threat with several equal options can take
            # the only option another one had).
            covered_unique = CoverageService._max_assignment(pairs, threshold)

            rows.append({
                'source': source,
                'expected_covered': int(coverage['covered'].sum()),
                'expected_covered_unique': len(covered_unique),
                'covered_unique_ids': sorted(int(i) for i in covered_unique),
                'expected_total': len(coverage),
                'distinct_candidates': int(coverage['candidates'].max()) if len(coverage) else 0,
                'candidates_matching_reference': int(matching)
            })

        return pd.DataFrame(rows)
