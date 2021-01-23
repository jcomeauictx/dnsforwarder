install: /etc/systemd/system/dnsforwarder.service
	sudo systemctl daemon-reload
	sudo systemctl enable dnsforwarder
	sudo systemctl start dnsforwarder
/etc/systemd/system/%: %
	sudo ln -s $(PWD)/$< $@
