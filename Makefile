PY ?= .venv/Scripts/python
ifeq ($(wildcard .venv/Scripts/python.exe),)
PY = .venv/bin/python
endif

.PHONY: test scan eval demo radar helpline
test:
	$(PY) -m pytest -q

scan:
	$(PY) -m scamshield.scan data/eval/sample.csv --out predictions.csv

eval:
	$(PY) -m scamshield.cli.eval data/eval/sample.csv

demo:
	$(PY) -m scamshield.api.demo
