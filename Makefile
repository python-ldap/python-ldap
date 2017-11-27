LCOV_INFO=build/lcov.info
LCOV_REPORT=build/lcov_report
LCOV_REPORT_OPTIONS=--show-details -no-branch-coverage \
	--title "python-ldap LCOV report"

.NOTPARALLEL:

.PHONY: all
all:

.PHONY: clean
clean:
	rm -rf build dist *.egg-info $(VENV) .tox MANIFEST
	rm -f .coverage .coverage.*
	find . \( -name '*.py[co]' -or -name '*.so*' -or -name '*.dylib' \) \
	    -delete
	find . -depth -name __pycache__ -exec rm -rf {} \;

# LCOV report (measuring test coverage for C code)
.PHONY: lcov-clean lcov-coverage lcov-report lcov-open lcov
lcov-clean:
	rm -rf $(LCOV_INFO) $(LCOV_REPORT)
	if [ -d build ]; then find build -name '*.gc??' -delete; fi

lcov-coverage:
	WITH_GCOV=1 tox -e py27,py36

$(LCOV_INFO):
	lcov --capture --directory build --output-file $(LCOV_INFO)

$(LCOV_REPORT): $(LCOV_INFO)
	genhtml --output-directory $(LCOV_REPORT) \
		$(LCOV_REPORT_OPTIONS) $(LCOV_INFO)

lcov-report: $(LCOV_REPORT)

lcov-open: $(LCOV_REPORT)
	xdg-open $(LCOV_REPORT)/index.html

lcov: lcov-clean
	$(MAKE) lcov-coverage
	$(MAKE) lcov-report
