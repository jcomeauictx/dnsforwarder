SYSTEMD := /etc/systemd/system
PYTHON ?= $(word 1, $(shell which python3 python python2))  # prefer python3
PYLINT ?= $(word 1, $(shell which pylint3 pylint true))
SOURCES := $(wildcard *.py)
check: $(SOURCES:.py=.pylint) $(SOURCES:.py=.doctest)
%.pylint: %.py
	$(PYLINT) $<
%.doctest: %.py
	$(PYTHON) -m doctest $<
install: $(SYSTEMD)/dnsforwarder.service $(SYSTEMD)/usbtether.service
	sudo systemctl daemon-reload
	sudo systemctl enable usbtether
	sudo systemctl enable dnsforwarder
/etc/systemd/system/%: %.template
	envsubst < $< | sudo tee $@
