"""Tests for tiers.py: confidence adjustment and tier rules."""
from app.ai.tiers import adjusted_confidence, assign_tier, changed_lines

BEFORE = 'import boto3\n\nKEY = "<<REDACTED_SECRET>>"\nclient = boto3.client("s3")\n'
AFTER_SMALL = 'import os\nimport boto3\n\nKEY = os.getenv("AWS_KEY")\nclient = boto3.client("s3")\n'


def edit(before, after):
    return {"file_path": "config.py", "original_content": before, "new_content": after}


def test_changed_lines_counts_modified_and_added():
    assert changed_lines(BEFORE, AFTER_SMALL) == 2          # import added + key line changed
    assert changed_lines(BEFORE, BEFORE) == 0


def test_specific_rule_keeps_confidence():
    assert adjusted_confidence({"rule_id": "aws-access-token", "file_path": "app/config.py", "confidence": 1.0}) == 1.0


def test_generic_rule_is_lowered():
    assert adjusted_confidence({"rule_id": "generic-api-key", "file_path": "app/config.py", "confidence": 1.0}) == 0.8


def test_test_folder_is_lowered():
    assert adjusted_confidence({"rule_id": "aws-access-token", "file_path": "tests/conf.py", "confidence": 1.0}) == 0.6


def test_example_file_name_is_lowered():
    assert adjusted_confidence({"rule_id": "aws-access-token", "file_path": "config_example.py", "confidence": 1.0}) == 0.6


def test_normal_words_containing_test_are_not_lowered():
    # "latest" contains "test" but is not a test file
    assert adjusted_confidence({"rule_id": "aws-access-token", "file_path": "latest_config.py", "confidence": 1.0}) == 1.0


def test_missing_confidence_defaults_to_one():
    assert adjusted_confidence({"rule_id": "github-pat", "file_path": "index.js"}) == 1.0


def test_small_change_high_confidence_is_auto_branch():
    assert assign_tier({}, edit(BEFORE, AFTER_SMALL), 0.9) == "auto_branch"


def test_small_change_medium_confidence_is_pr_review():
    assert assign_tier({}, edit(BEFORE, AFTER_SMALL), 0.7) == "pr_review"


def test_big_change_is_pr_review_even_with_high_confidence():
    big = AFTER_SMALL + "def helper():\n    return 1\n"
    assert assign_tier({}, edit(BEFORE, big), 1.0) == "pr_review"