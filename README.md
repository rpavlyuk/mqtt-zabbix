SUMMARY
=======

A small daemon to listen for particular MQTT messages, and relay them to a Zabbix server

Original by Kyle Gordon (https://github.com/kylegordon/mqtt-zabbix),
modifications by Markku Leiniö in 2019:
- Modified for Python 3 and systemd
- Removed the parsing of item-specific hosts
- plus other style adjustments


INSTALL DEPENDENCES
=======

```
sudo apt-get install git python3-pip
sudo pip3 install paho-mqtt
sudo pip3 install zbxsend
```
## Alternatively this...
```
git clone https://github.com/pistolero/zbxsend /tmp/zbxsend
cd /tmp/zbxsend
sudo python setup.py install
```

# Install MQTT Zabbix
```
sudo -i
mkdir /etc/mqtt-zabbix/
git clone git://github.com/markkuleinio/mqtt-zabbix.git /opt/mqtt-zabbix/
cp /opt/mqtt-zabbix/mqtt-zabbix.cfg.example /etc/mqtt-zabbix/mqtt-zabbix.cfg
cp /opt/mqtt-zabbix/mqtt-zabbix.init /etc/init.d/mqtt-zabbix
## Edit /etc/mqtt-zabbix/mqtt-zabbix.cfg to suit
cp /opt/mqtt-zabbix/items.csv.example /etc/mqtt-zabbix/items.csv
## Edit /etc/mqtt-zabbix/items.csv to suit. Be sure to avoid spaces, and keep it as one key per topic
/etc/init.d/mqtt-zabbix start
```

CONFIGURE
=========

Configuration is stored in /etc/mqtt-zabbix/mqtt-zabbix.cfg

Message topics are mapped to Zabbix item names, and are stored in `/etc/mqtt-zabbix/items.csv`.
When setting up a Zabbix item, ensure you use item type of Zabbix trapper, and check the "Type of information" field is defined correctly. MQTT can transport all sorts of information, and will happily try to deliver a string to your integer data type!
zbx_mqtt_template.xml is an example Zabbix template
