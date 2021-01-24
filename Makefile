install: /etc/systemd/system/dnsforwarder.service
	sudo systemctl daemon-reload
	sudo systemctl enable dnsforwarder
	sudo systemctl start dnsforwarder &  # waits for tun0 to come online
/etc/systemd/system/%: %.template
	envsubst < $< | sudo tee $@
