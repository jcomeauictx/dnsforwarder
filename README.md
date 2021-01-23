# dnsforwarder -- fix for DNS blocking on some cellular networks

In order for systemctl to start the script on modern Linux systems, renaming
devices must be disabled. One way to do this is
`sudo ln -s /dev/null /etc/udev/rules.d/80-net-setup-link.rules`, then restart
udev with `sudo systemd restart udev`. That will make sure the tether interface
is named usb0 rather than something like enp0s29f7u1.
