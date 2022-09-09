CURRENT_GRYPE_COMMIT = $(shell git rev-parse --verify HEAD)

.PHONY: validate
validate: venv
	. venv/bin/activate; python ./gate.py

.PHONY: capture
capture: venv
	. venv/bin/activate; CURRENT_GRYPE_COMMIT=$(CURRENT_GRYPE_COMMIT) yardstick -v result capture -r pr-vs-latest

venv: venv/touchfile

venv/touchfile: requirements.txt
	test -d venv || virtualenv venv
	. venv/bin/activate; pip install -e ../../../yardstick
	# . venv/bin/activate; pip install -Ur requirements.txt
	touch venv/touchfile

clean:
	rm -rf venv
	find -iname "*.pyc" -delete

# with no SBOM input...
# make capture  106.34s user 56.78s system 57% cpu 4:42.03 total

# with SBOM inpurt...
# make capture  33.33s user 11.13s system 75% cpu 59.206 total
