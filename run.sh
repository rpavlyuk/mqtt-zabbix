#!/bin/bash

docker run --rm --name mqtt-zabbix --hostname mqtt-zabbix --tty --privileged  $@ rpavlyuk/mqtt-zabbix
