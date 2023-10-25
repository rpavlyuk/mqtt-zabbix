SUMMARY
=======

A small daemon to listen for particular MQTT messages, and relay them to a Zabbix server

Original by Kyle Gordon (https://github.com/kylegordon/mqtt-zabbix),
modifications by Markku Leiniö in 2019:
- Modified for Python 3 and systemd
- Forked zbxsend from https://github.com/pistolero/zbxsend (for Python 3 fixes)
- Removed parsing of item-specific hosts
- Added LLD-based template (for Zabbix 4.4+) to setup all the items automatically in Zabbix
- Added logrotate support
- plus style adjustments

Additions by Roman Pavlyuk in 2023:
- multi-host support: default host is set in settings file (.cfg), but each item can override the host if the one is specified via colon (:) sign (see example of csv file)
- stability and compatibility improvement with the lastest versions of Python

Implementation tested with Debian Linux 10 (Buster) and Zabbix 4.4, Fedora 38 and Zabbix 6.x

INSTALL DEPENDENCIES
=======

```
sudo apt-get install git python3-pip
sudo pip3 install paho-mqtt

git clone https://github.com/markkuleinio/zbxsend /tmp/zbxsend
cd /tmp/zbxsend
sudo pip3 install .
```

Configure Zabbix
========
(optional)
1. Inspect and import the template from `Zabbix-Template-App-EmonPi-discovery.xml`.
1. Create a host in Zabbix and link the imported template to it. This host will be having all the
items monitored by mqtt-zabbix. The items are automatically created with LLD rules.

Install and Configure MQTT-Zabbix
========

```
sudo -i
mkdir /etc/mqtt-zabbix/
git clone git://github.com/rpavlyuk/mqtt-zabbix.git /opt/mqtt-zabbix/
cp /opt/mqtt-zabbix/mqtt-zabbix.cfg.example /etc/mqtt-zabbix/mqtt-zabbix.cfg
cp /opt/mqtt-zabbix/items.csv.example /etc/mqtt-zabbix/items.csv
```

Edit `/etc/mqtt-zabbix/mqtt-zabbix.cfg` and `/etc/mqtt-zabbix/items.csv` according
to your setup. Be sure to avoid line spaces (means, empty lines) in `items.csv`, even at the end of the file, and keep it as one line per topic.

```
adduser --system --home /opt/mqtt-zabbix --gecos "mqtt-zabbix" --disabled-login --group mqtt-zbx
touch /var/log/mqtt-zabbix.log
chown mqtt-zbx:mqtt-zbx /var/log/mqtt-zabbix.log
cp /opt/mqtt-zabbix/mqtt-zabbix.service /etc/systemd/system/mqtt-zabbix.service
cp /opt/mqtt-zabbix/mqtt-zabbix.logrotate /etc/logrotate.d/mqtt-zabbix
systemctl daemon-reload
systemctl start mqtt-zabbix
systemctl enable mqtt-zabbix
```

In case of problems, try `journalctl -u mqtt-zabbix` and see `/var/log/mqtt-zabbix.log`.
