.NOTPARALLEL:

.PHONY: all
all:

.PHONY: clean
clean:
	rm -rf build dist *.egg-info $(VENV) .tox
	rm -f .coverage .coverage.*
	find . -name '*.py[co]' -or -name '*.so*' -or -name '*.dylib' -delete
	find . -depth -name __pycache__ -exec rm -rf {} \;
