"""Pure algorithm: additive evidence plus a separate confidence multiplier.

Unknown inputs create intervals, not invented measurements. Changes require a new version.
"""
import math

VERSION = 'exposure-v1.0'
WEIGHTS = {'cvss': 30, 'epss': 20, 'kev': 20, 'exposure': 15, 'criticality': 10, 'finding_age': 5}
EXPOSURE = {'INTERNAL': .4, 'INTERNET': 1.0}
CRITICALITY = {'LOW': .25, 'MEDIUM': .5, 'HIGH': .75, 'CRITICAL': 1.0}
CONFIDENCE = {'LOW': .5, 'MODERATE': .75, 'HIGH': 1.0}


def numeric(value, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and 0 <= value <= maximum else None


def calculate(values: dict, sources: dict) -> dict:
    """Return the complete replayable component ledger for one issue."""
    normalized = {
        'cvss': None if numeric(values.get('cvss'), 10) is None else values['cvss'] / 10,
        'epss': numeric(values.get('epss'), 1),
        'kev': float(values['kev']) if type(values.get('kev')) is bool else None,
        'exposure': EXPOSURE.get(values.get('exposure')),
        'criticality': CRITICALITY.get(values.get('criticality')),
        'finding_age': None if numeric(values.get('finding_age'), 1_000_000) is None else min(values['finding_age'] / 90, 1),
    }
    components = []
    for name, weight in WEIGHTS.items():
        value = normalized[name]
        components.append({'name': name, 'raw': values.get(name), 'normalized': value,
                           'weight': weight, 'lower': 0 if value is None else weight * value,
                           'upper': weight if value is None else weight * value,
                           'known': value is not None, 'source': sources.get(name, 'Not available')})
    factor = CONFIDENCE.get(values.get('confidence'))
    confidence = {'name': 'confidence', 'raw': values.get('confidence'), 'normalized': factor,
                  'weight': None, 'lower': factor if factor is not None else .5,
                  'upper': factor if factor is not None else 1.0, 'known': factor is not None,
                  'source': sources.get('confidence', 'No identity-linkage evidence'), 'operation': 'multiply'}
    base_lower = sum(c['lower'] for c in components)
    base_upper = sum(c['upper'] for c in components)
    lower = round(base_lower * confidence['lower'], 2)
    upper = round(base_upper * confidence['upper'], 2)
    components.append(confidence)
    complete = all(c['known'] for c in components)
    return {'lower': lower, 'upper': upper, 'score': lower if complete else None,
            'base_lower': round(base_lower, 2), 'base_upper': round(base_upper, 2),
            'status': 'COMPLETE' if complete else 'INCOMPLETE', 'components': components,
            'band': band(lower) if band(lower) == band(upper) else 'UNCERTAIN'}


def band(value: float) -> str:
    return 'CRITICAL' if value >= 80 else 'HIGH' if value >= 60 else 'MEDIUM' if value >= 30 else 'LOW'
