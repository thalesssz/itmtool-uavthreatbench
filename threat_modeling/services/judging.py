"""Run many judge calls: remembered judgments first, the rest in parallel, failures reported."""
import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from langchain_core.messages import BaseMessage

from ..api.llm_client import LLMClient
from ..config.settings import JUDGMENT_CACHE_PATH, LLM_SEED, LLM_TEMPERATURE
from ..models.comparison_models import ThreatComparisonResponse


class JudgmentCache:
    """
    Judgments already made, on disk, keyed by everything the judge reads.

    The key covers the provider, the model, temperature and seed, and the full
    text of every message (so a new prompt version, scenario description or
    threat text is a new key). The same key always gets the same answer back,
    which is what makes a repeated run cheap and reproducible.
    """

    def __init__(self, path: str = JUDGMENT_CACHE_PATH):
        self._lock = threading.Lock()
        self._db = None
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
            self._db.execute(
                'CREATE TABLE IF NOT EXISTS judgments ('
                ' key TEXT PRIMARY KEY, kind TEXT, provider TEXT, model TEXT,'
                ' is_similar INTEGER, similarity_score REAL, explanation TEXT,'
                ' answered_by TEXT, call_id TEXT, cost REAL, judged_at TEXT)')
            self._db.commit()
        except sqlite3.Error as e:
            print(f"Judgment cache disabled ({path}): {e}")
            self._db = None

    @staticmethod
    def key(kind: str, provider: str, model: str, messages: List[BaseMessage]) -> str:
        payload = json.dumps([kind, provider, model, LLM_TEMPERATURE, LLM_SEED,
                              [(m.type, m.content) for m in messages]], ensure_ascii=False)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def get(self, key: str) -> Optional[Dict]:
        if self._db is None:
            return None
        with self._lock:
            row = self._db.execute(
                'SELECT is_similar, similarity_score, explanation, answered_by, call_id, cost, judged_at'
                ' FROM judgments WHERE key = ?', (key,)).fetchone()
        if row is None:
            return None
        return {'is_similar': bool(row[0]), 'similarity_score': row[1], 'explanation': row[2],
                'answered_by': row[3], 'call_id': row[4], 'cost': row[5], 'judged_at': row[6]}

    def put(self, key: str, kind: str, provider: str, model: str, result: Dict) -> None:
        if self._db is None:
            return
        with self._lock:
            self._db.execute(
                'INSERT OR REPLACE INTO judgments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (key, kind, provider, model, int(result['is_similar']), result['similarity_score'],
                 result['explanation'], result['answered_by'], result['call_id'], result['cost'],
                 result['judged_at']))
            self._db.commit()


def judge_all(client: LLMClient, message_lists: List[List[BaseMessage]], kind: str,
              use_cache: bool = True, cache: Optional[JudgmentCache] = None,
              label: str = 'judge') -> Tuple[List[Dict], Dict]:
    """
    Judge every message list and return one result per list, in the same order.

    Remembered judgments are reused (unless use_cache is False); identical
    prompts within the run are judged once; the rest run in parallel when the
    provider allows it. A call that still fails after the retries is reported
    with error set and is not remembered, so running again retries only it.

    Returns:
        (results, stats). Each result has is_similar, similarity_score,
        explanation, answered_by, call_id, cost, judged_at, from_cache and
        error. stats has total, distinct, reused, judged, failed, seconds and
        cost (of the calls made now, when the provider reports it).
    """
    started = time.time()
    cache = cache if cache is not None else JudgmentCache()
    keys = [JudgmentCache.key(kind, client.provider, client.model_name, m) for m in message_lists]

    found = {}
    todo = {}
    for key, messages in zip(keys, message_lists):
        if key in found or key in todo:
            continue
        cached = cache.get(key) if use_cache else None
        if cached is not None:
            found[key] = dict(cached, from_cache=True, error='')
        else:
            todo[key] = messages

    done = [0]
    done_lock = threading.Lock()

    def judge(item):
        key, messages = item
        try:
            response, meta = client.with_retries(
                lambda: client.invoke_with_structure_meta(messages, ThreatComparisonResponse))
            result = {'is_similar': bool(response.is_similar),
                      'similarity_score': float(response.similarity_score),
                      'explanation': response.explanation,
                      'answered_by': meta.get('model') or client.model_name,
                      'call_id': meta.get('call_id') or '',
                      'cost': meta.get('cost'),
                      'judged_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                      'from_cache': False, 'error': ''}
            cache.put(key, kind, client.provider, client.model_name, result)
        except Exception as e:
            print(f"Error judging ({label}): {str(e)}")
            result = {'is_similar': False, 'similarity_score': 0.0,
                      'explanation': f'Error during judgment: {str(e)}',
                      'answered_by': '', 'call_id': '', 'cost': None, 'judged_at': '',
                      'from_cache': False, 'error': str(e) or type(e).__name__}
        with done_lock:
            done[0] += 1
            if done[0] % 25 == 0 or done[0] == len(todo):
                print(f"[{label}] {done[0]}/{len(todo)} judged now, {len(found)} from memory")
        return key, result

    for key, result in client.map_ordered(judge, list(todo.items())):
        found[key] = result

    results = [found[key] for key in keys]
    fresh = [found[key] for key in todo]
    costs = [r['cost'] for r in fresh if r['cost'] is not None]
    stats = {
        'total': len(keys),
        'distinct': len(found),
        'reused': len(found) - len(todo),
        'judged': sum(1 for r in fresh if not r['error']),
        'failed': sum(1 for r in fresh if r['error']),
        'seconds': round(time.time() - started, 1),
        'cost': round(sum(costs), 4) if costs else None,
    }
    return results, stats
