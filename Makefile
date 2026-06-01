.PHONY: test lint format safety run-dashboard clean

test:
	pytest -q

lint:
	ruff check .

format:
	ruff format .

safety:
	pytest -q tests/test_safety_static.py

run-dashboard:
	streamlit run app/dashboard.py

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__
