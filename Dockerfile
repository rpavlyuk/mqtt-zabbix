FROM fedora:latest

# Refresh container
RUN dnf update -y
RUN dnf install -y ca-certificates tzdata less vim
RUN /usr/bin/update-ca-trust

ENV container=docker

# install Python runtimes and SDK
RUN dnf install -y git python3 python3-pip perl

# install MQTT Client
RUN pip3 install paho-mqtt

# Install ZBXSend
RUN mkdir -p /build/zbxsend
RUN git clone https://github.com/markkuleinio/zbxsend /build/zbxsend/
RUN cd /build/zbxsend && pip3 install .

# Prepare MQTT Zabbix
RUN mkdir -p /etc/mqtt-zabbix

COPY mqtt-zabbix.cfg.example /etc/mqtt-zabbix/mqtt-zabbix.cfg
COPY items.csv.example /etc/mqtt-zabbix/items.csv
COPY mqtt-zabbix.py /usr/local/bin/
RUN chmod 755 /usr/local/bin/mqtt-zabbix.py 

# Configure MQTT Zabbix
# Alter default settings in config file(s)
RUN perl -pi -e "s/\/var\/log\/mqtt-zabbix\.log/\/dev\/stdout/gi" /etc/mqtt-zabbix/mqtt-zabbix.cfg

VOLUME ["/etc/mqtt-zabbix"]

CMD ["/usr/local/bin/mqtt-zabbix.py"]
