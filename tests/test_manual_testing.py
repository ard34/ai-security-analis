from core.manual_testing import recommendations_for_findings
from core.models import Finding


def test_manual_recommendations_are_defensive():
    recs = recommendations_for_findings([Finding(title="Potential auth issue")])
    assert recs
    assert "bypass" not in recs[0].lower()

