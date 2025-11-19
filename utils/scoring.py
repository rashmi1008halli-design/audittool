# utils/scoring.py

def calculate_score(results):
    """
    Calculate a simple security score.
    results: dict with keys 'public_buckets', 'root_mfa', 'open_sgs'
    """
    score = 100

    # Deduct points for public buckets
    score -= len(results.get('public_buckets', [])) * 20

    # Deduct points if root MFA is not enabled
    if not results.get('root_mfa', True):
        score -= 30

    # Deduct points for open security groups
    score -= len(results.get('open_sgs', [])) * 10

    # Ensure score is between 0 and 100
    score = max(0, min(100, score))
    return score
