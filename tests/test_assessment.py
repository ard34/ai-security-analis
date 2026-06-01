from core.assessment import Assessment, load_assessment, save_assessment


def test_assessment_approval_round_trip(tmp_path):
    path = tmp_path / "assessment.json"
    assessment = Assessment(name="test", allowed_targets=["example.com"]).approve()
    save_assessment(assessment, path)
    assert load_assessment(path).approved is True

