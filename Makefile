# SecureMailScope — developer convenience targets.
# Override the interpreter with:  make demo PYTHON=py -3
PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help install install-all demo samples analyze dashboard test clean

help:  ## Show this help
	@echo "SecureMailScope targets:"
	@echo "  make install      core install (editable)"
	@echo "  make install-all  install with ml + pdf + dashboard extras"
	@echo "  make demo         zero-credential end-to-end demo (writes samples/)"
	@echo "  make samples      generate the synthetic PCAP corpus only"
	@echo "  make analyze      analyze samples/pcaps/all.pcap into out/"
	@echo "  make dashboard    launch the local dashboard (needs fastapi/uvicorn)"
	@echo "  make test         run the stdlib unittest suite"
	@echo "  make clean        remove build/report/cache artifacts"

install:  ## Editable core install
	$(PYTHON) -m pip install -e .

install-all:  ## Editable install with all optional features
	$(PYTHON) -m pip install -e ".[all]"

demo:  ## Generate + analyze + report, end to end
	$(PYTHON) -m securemailscope demo

samples:  ## Write the synthetic PCAP corpus
	$(PYTHON) -m securemailscope gen-samples

analyze: samples  ## Analyze the combined capture into out/
	$(PYTHON) -m securemailscope analyze samples/pcaps/all.pcap --out-dir out

dashboard:  ## Launch the interactive dashboard on 127.0.0.1:8000
	$(PYTHON) -m securemailscope dashboard

test:  ## Run the test suite (standard library only)
	$(PYTHON) -m unittest discover -s tests -t .

clean:  ## Remove generated artifacts
	rm -rf out samples/pcaps samples/securemailscope_demo.* \
	       build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
