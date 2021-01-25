SYSTEMD := /etc/systemd/system
export
install: $(SYSTEMD)/dnsforwarder.service $(SYSTEMD)/usbtether.service
	sudo systemctl daemon-reload
	sudo systemctl enable usbtether
	sudo systemctl enable dnsforwarder
/etc/systemd/system/%: %.template
	envsubst < $< | sudo tee $@
