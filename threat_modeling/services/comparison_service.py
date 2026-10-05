"""Comparison Service - Compare TMT tool threats with AI analysis results using LLM."""
import pandas as pd
from typing import Dict, List, Optional, Tuple

from ..api.llm_client import LLMClient
from ..api.message_builder import generate_comparison_messages
from ..models.comparison_models import ThreatComparisonResponse
from .judging import judge_all


class ComparisonService:
    """Service for pairing and comparing TMT threats with AI threats (similarity via LLM)."""

    def __init__(self):
        """Initialize the comparison service."""
        self.last_stats = {}
    
    def prepare_comparison_data(self, tmt_threats_df: pd.DataFrame, ai_results_df: pd.DataFrame) -> Tuple[List[Dict], List[Dict], List[Tuple]]:
        """
        Prepare data for comparison by grouping threats by DataFlow Name and Category.
        
        Args:
            tmt_threats_df: DataFrame with TMT threats (must have 'DataFlow', 'category', 'description')
            ai_results_df: DataFrame with AI results (must have 'data_flow_name', 'category', 'description')
            
        Returns:
            Tuple of:
            - List of TMT-only threats (dicts)
            - List of AI-only threats (dicts)
            - List of pairs to compare (tuples of (tmt_dict, ai_dict))
        """
        # Normalize column names
        tmt_df = tmt_threats_df.copy()
        ai_df = ai_results_df.copy()
        
        # Ensure consistent column names
        if 'DataFlow' in tmt_df.columns:
            tmt_df['dataflow_name'] = tmt_df['DataFlow']
        elif 'dataflow_name' not in tmt_df.columns:
            tmt_df['dataflow_name'] = tmt_df.get('DataFlow Name', '')
        
        if 'category' not in tmt_df.columns:
            tmt_df['category'] = tmt_df.get('Category', '')
        if 'description' not in tmt_df.columns:
            tmt_df['description'] = tmt_df.get('Description', '')
        
        # Normalize AI DataFrame
        if 'data_flow_name' not in ai_df.columns:
            ai_df['data_flow_name'] = ai_df.get('DataFlow Name', '')
        if 'category' not in ai_df.columns:
            ai_df['category'] = ai_df.get('Category', '')
        if 'description' not in ai_df.columns:
            ai_df['description'] = ai_df.get('Description', '')
        
        # Create keys for grouping: (dataflow_name, category)
        tmt_df['key'] = tmt_df.apply(
            lambda row: (str(row.get('dataflow_name', '')).strip().lower(), 
                        str(row.get('category', '')).strip().lower()), 
            axis=1
        )
        ai_df['key'] = ai_df.apply(
            lambda row: (str(row.get('data_flow_name', '')).strip().lower(), 
                        str(row.get('category', '')).strip().lower()), 
            axis=1
        )
        
        # Convert to dicts for easier manipulation
        tmt_dict = {}
        for _, row in tmt_df.iterrows():
            key = row['key']
            if key not in tmt_dict:
                tmt_dict[key] = []
            tmt_dict[key].append({
                'dataflow_name': row.get('dataflow_name', ''),
                'category': row.get('category', ''),
                'description': row.get('description', ''),
                'source': 'tmt'
            })
        
        ai_dict = {}
        for _, row in ai_df.iterrows():
            key = row['key']
            if key not in ai_dict:
                ai_dict[key] = []
            ai_dict[key].append({
                'dataflow_name': row.get('data_flow_name', ''),
                'category': row.get('category', ''),
                'description': row.get('description', ''),
                'source': 'ai'
            })
        
        # Find matches and exclusives
        tmt_only = []
        ai_only = []
        pairs_to_compare = []
        
        all_keys = set(tmt_dict.keys()) | set(ai_dict.keys())
        
        for key in all_keys:
            tmt_threats = tmt_dict.get(key, [])
            ai_threats = ai_dict.get(key, [])
            
            if tmt_threats and ai_threats:
                # Both exist - create pairs for comparison
                # Compare each TMT threat with each AI threat for this key
                for tmt_threat in tmt_threats:
                    for ai_threat in ai_threats:
                        pairs_to_compare.append((tmt_threat, ai_threat))
            elif tmt_threats:
                # Only TMT has threats for this key
                tmt_only.extend(tmt_threats)
            elif ai_threats:
                # Only AI has threats for this key
                ai_only.extend(ai_threats)
        
        return tmt_only, ai_only, pairs_to_compare
    
    def compare_threats_pair(self, tmt_threat: Dict, ai_threat: Dict, llm_client: LLMClient) -> ThreatComparisonResponse:
        """
        Compare a pair of threats using LLM.
        
        Args:
            tmt_threat: Dict with TMT threat data (dataflow_name, category, description)
            ai_threat: Dict with AI threat data (dataflow_name, category, description)
            llm_client: LLMClient instance configured with provider/model
            
        Returns:
            ThreatComparisonResponse with comparison results
        """
        tmt_desc = tmt_threat.get('description', '')
        ai_desc = ai_threat.get('description', '')
        category = tmt_threat.get('category', '') or ai_threat.get('category', '')
        dataflow_name = tmt_threat.get('dataflow_name', '') or ai_threat.get('dataflow_name', '')
        
        # Generate messages
        messages = generate_comparison_messages(tmt_desc, ai_desc, category, dataflow_name)
        
        # Call LLM with structured output
        comparison_response = llm_client.invoke_with_structure(messages, ThreatComparisonResponse)
        
        return comparison_response
    
    def run_comparison(self, tmt_threats_df: pd.DataFrame, ai_results_df: pd.DataFrame,
                      provider: str, model_name: str, api_key: Optional[str] = None,
                      server_ip: Optional[str] = None, use_cache: bool = True) -> pd.DataFrame:
        """
        Run complete comparison between TMT threats and AI analysis results.

        Args:
            tmt_threats_df: DataFrame with TMT threats
            ai_results_df: DataFrame with AI results
            provider: LLM provider name
            model_name: Model name to use
            api_key: API key (optional)
            server_ip: Server IP for Ollama (optional)
            use_cache: Reuse remembered judgments (False judges everything again)

        Returns:
            DataFrame with comparison results containing columns:
            - dataflow_name, category
            - tmt_description, ai_description
            - is_similar, similarity_score, explanation
            - source: "both", "tmt_only", "ai_only"
            - answered_by, from_cache, error (judged pairs)

        After the run, self.last_stats holds the counts of judgments made now,
        reused from memory and failed, with the time and the cost.
        """
        # Prepare data
        tmt_only, ai_only, pairs_to_compare = self.prepare_comparison_data(tmt_threats_df, ai_results_df)

        # Initialize LLM client
        llm_client = LLMClient(
            provider=provider,
            model_name=model_name,
            api_key=api_key,
            server_ip=server_ip
        )

        # Same messages as compare_threats_pair, judged together (memory, parallel calls)
        message_lists = []
        for tmt_threat, ai_threat in pairs_to_compare:
            message_lists.append(generate_comparison_messages(
                tmt_threat.get('description', ''), ai_threat.get('description', ''),
                tmt_threat.get('category', '') or ai_threat.get('category', ''),
                tmt_threat.get('dataflow_name', '') or ai_threat.get('dataflow_name', '')))
        results, self.last_stats = judge_all(llm_client, message_lists, kind='comparison',
                                             use_cache=use_cache, label='comparison')

        comparison_results = []
        for (tmt_threat, ai_threat), result in zip(pairs_to_compare, results):
            comparison_results.append({
                'dataflow_name': tmt_threat.get('dataflow_name', '') or ai_threat.get('dataflow_name', ''),
                'category': tmt_threat.get('category', '') or ai_threat.get('category', ''),
                'tmt_description': tmt_threat.get('description', ''),
                'ai_description': ai_threat.get('description', ''),
                'is_similar': result['is_similar'],
                'similarity_score': result['similarity_score'],
                'explanation': result['explanation'],
                'source': 'both',
                'answered_by': result['answered_by'],
                'from_cache': result['from_cache'],
                'error': result['error']
            })

        # Add TMT-only threats
        for threat in tmt_only:
            comparison_results.append({
                'dataflow_name': threat.get('dataflow_name', ''),
                'category': threat.get('category', ''),
                'tmt_description': threat.get('description', ''),
                'ai_description': '',
                'is_similar': False,
                'similarity_score': 0.0,
                'explanation': 'Threat only found in TMT',
                'source': 'tmt_only'
            })
        
        # Add AI-only threats
        for threat in ai_only:
            comparison_results.append({
                'dataflow_name': threat.get('dataflow_name', ''),
                'category': threat.get('category', ''),
                'tmt_description': '',
                'ai_description': threat.get('description', ''),
                'is_similar': False,
                'similarity_score': 0.0,
                'explanation': 'Threat only found in AI analysis',
                'source': 'ai_only'
            })
        
        return pd.DataFrame(comparison_results)

