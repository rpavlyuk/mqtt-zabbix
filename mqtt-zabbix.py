#!/usr/bin/env python3

__author__ = "Kyle Gordon"
__copyright__ = "Copyright (C) Kyle Gordon"

import os
import logging
import logging.handlers
import signal
import socket
import time
import sys
import csv

import paho.mqtt.client as mqtt
import configparser

import traceback

from datetime import datetime, timedelta

from zbxsend import Metric, send_to_zabbix

# LLD data
lld_data = {}
last_stale_check = 0
last_full_lld_send = 0
LLD_SEND_INTERVAL = 3600

# Read the config file
config = configparser.RawConfigParser()
config.read("/etc/mqtt-zabbix/mqtt-zabbix.cfg")

# Use ConfigParser to pick out the settings
DEBUG = config.getboolean("global", "debug")
LOGFILE = config.get("global", "logfile")
MQTT_HOST = config.get("global", "mqtt_host")
MQTT_PORT = config.getint("global", "mqtt_port")
MQTT_USER = config.get("global", "mqtt_user")
MQTT_PASSWORD = config.get("global", "mqtt_password")
MQTT_TOPIC = config.get("global", "mqtt_topic")

KEYFILE = config.get("global", "keyfile")
KEYHOST = config.get("global", "keyhost")
ZBXSERVER = config.get("global", "zabbix_server")
ZBXPORT = config.getint("global", "zabbix_port")

APPNAME = "mqtt-zabbix"
PRESENCETOPIC = "clients/" + socket.getfqdn() + "/" + APPNAME + "/state"
client_id = APPNAME + "_%d" % os.getpid()
mqttc = mqtt.Client(client_id="client_id")

LOGFORMAT = "%(asctime)-15s %(message)s"

if __name__ == "__main__":
    logger = logging.getLogger()
else:
    logger = logging.getLogger(__name__)

if DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
fileformatter = logging.Formatter(LOGFORMAT)
filehandler = logging.handlers.WatchedFileHandler(LOGFILE)
filehandler.setFormatter(fileformatter)
logger.addHandler(filehandler)

logger.info("Starting " + APPNAME)
logger.info("INFO MODE")
logger.debug("DEBUG MODE")

# All the MQTT callbacks start here


def on_publish(mosq, obj, mid):
    """
    What to do when a message is published
    """
    logger.debug("MID " + str(mid) + " published.")


def on_subscribe(mosq, obj, mid, qos_list):
    """
    What to do in the event of subscribing to a topic"
    """
    logger.debug("Subscribe with mid " + str(mid) + " received.")


def on_unsubscribe(mosq, obj, mid):
    """
    What to do in the event of unsubscribing from a topic
    """
    logger.debug("Unsubscribe with mid " + str(mid) + " received.")


def on_connect(mosq, obj, flags, result_code):
    """
    Handle connections (or failures) to the broker.
    This is called after the client has received a CONNACK message
    from the broker in response to calling connect().
    The parameter rc is an integer giving the return code:

    0: Success
    1: Refused – unacceptable protocol version
    2: Refused – identifier rejected
    3: Refused – server unavailable
    4: Refused – bad user name or password (MQTT v3.1 broker only)
    5: Refused – not authorised (MQTT v3.1 broker only)
    """
    logger.debug("on_connect RC: " + str(result_code))
    if result_code == 0:
        logger.info("Connected to %s:%s", MQTT_HOST, MQTT_PORT)
        # Publish retained LWT as per
        # http://stackoverflow.com/q/97694
        # See also the will_set function in connect() below
        mqttc.publish(PRESENCETOPIC, "1", retain=True)
        process_connection()
    elif result_code == 1:
        logger.info("Connection refused - unacceptable protocol version")
        cleanup()
    elif result_code == 2:
        logger.info("Connection refused - identifier rejected")
        cleanup()
    elif result_code == 3:
        logger.info("Connection refused - server unavailable")
        logger.info("Retrying in 30 seconds")
        time.sleep(30)
    elif result_code == 4:
        logger.info("Connection refused - bad user name or password")
        cleanup()
    elif result_code == 5:
        logger.info("Connection refused - not authorised")
        cleanup()
    else:
        logger.warning("Something went wrong. RC:" + str(result_code))
        cleanup()


def on_disconnect(mosq, obj, result_code):
    """
    Handle disconnections from the broker
    """
    if result_code == 0:
        logger.info("Clean disconnection")
    else:
        logger.info("Unexpected disconnection! Reconnecting in 5 seconds")
        logger.debug("Result code: %s", result_code)
        time.sleep(5)


def on_message(mosq, obj, msg):
    """
    What to do when the client recieves a message from the broker
    """
    try:
        m = msg.payload.decode()
    except:
        m = "UNABLE TO DECODE"
    logger.debug("Received: " + m +
                 " received on topic " + msg.topic +
                 " with QoS " + str(msg.qos))
    try:
        process_message(msg)
    except:
        logger.error("ERROR on_message")
        logger.error(traceback.format_exc())


def on_log(mosq, obj, level, string):
    """
    What to do with debug log output from the MQTT library
    """
    logger.debug(string)

# End of MQTT callbacks


def ensure_float(variable):
    """
    Ensure string variables which in fact are number are converted to numbers
    """
    if isinstance(variable, str):  # Check if variable is a string
        try:
            return float(variable)  # Try to cast to float
        except ValueError:
            logger.debug("Variable is actually a string: " + str(variable))
            return variable  # Return the original variable
    elif isinstance(variable, (int, float)):  # Check if variable is an int or float
        return float(variable)  # Cast to float
    else:
        logger.debug("Variable is neither a string not a number: " + str(variable))
        return variable  # Return the original variable

def process_connection():
    """
    What to do when a new connection is established
    """
    logger.debug("Processing connection")
    mqttc.subscribe(MQTT_TOPIC, 2)


def send_lld_data(discovery_key_name, datadict):

    for host, items in KeyMap.items_by_host.items():

        output = "[\n"
        first = True
        for topic in sorted(datadict.keys()):
            if topic not in items:
                continue
            logger.debug("Processing topic {}".format(topic))
            item = get_zabbix_item(topic);
            if not first:
                output += ",\n"
            first = False
            output += "\t{\n"
            output += '\t\t"{}":"{}",\n'.format("{#ITEMNAME}",item)
            output += '\t\t"{}":"{}"\n'.format("{#ITEMDESCR}",KeyMap.item_names[topic])
            output += "\t}"
        output += "\n]\n"
        logger.debug("Generated LLD data:\n{}".format(output))
        logger.info("Sending LLD data for {} (len={}) for host {}".format(
            discovery_key_name,
            len(datadict),
            KEYHOST
            ))
        send_to_zabbix(
            [Metric(host, discovery_key_name, output)],
             ZBXSERVER,
            ZBXPORT
        )
    return


def get_key_type(topic):

    lst_topic = topic.split("/")

    metric = lst_topic[-1] 
    sensorname = lst_topic[1]

    if metric == "battery":
        return "battery"
    elif metric.startswith("temperature") or metric == "external temperature":
        return "temperature"
    elif metric == "humidity":
        return "humidity"
    elif metric == "rssi" or metric == "linkquality":
        return "rssi"
    else:
        return "general"


def lld_update(topic):
    global lld_data
    global last_full_lld_send
    global last_stale_check
    keytype = get_key_type(topic)
    if keytype not in lld_data:
        # Initialize the dict if needed
        lld_data[keytype] = {}
    time_now = time.monotonic()
    send_needed = False
    if topic not in lld_data[keytype]:
        send_needed = True
    # Set/update the timestamp
    lld_data[keytype][topic] = time_now
    # Do the stale topic check only once a minute
    if last_stale_check+60 < time_now:
        last_stale_check = time_now
        # Check all keytypes for any outdated topics
        for kt in lld_data:
            for t in lld_data[kt]:
                if lld_data[kt][t]+LLD_SEND_INTERVAL < time_now:
                    # No data for that topic for some time, remove it
                    del lld_data[kt][t]
        if last_full_lld_send+LLD_SEND_INTERVAL < time_now:
            logger.info("Sending full LLD updates (every {} seconds)".format(LLD_SEND_INTERVAL))
            last_full_lld_send = time_now
            # Send LLD data for all keytypes
            for keytype in lld_data:
                send_lld_data("mqtt-zabbix.discovery.{}".format(keytype), lld_data[keytype])
            # No need to continue further, sent all already
            return
    if send_needed:
        # New topic was added so send this LLD data anyway
        send_lld_data("mqtt-zabbix.discovery.{}".format(keytype), lld_data[keytype])
    return


def get_zabbix_item(topic):

    lst_topic = topic.split("/")

    key_path = lst_topic[2]

    if len(lst_topic) > 3:
        i = 3
        while i < len(lst_topic):
            key_path += ("." + lst_topic[i])
            i+=1

    return "mqtt-zabbix.{}[{}.{}]".format(
        get_key_type(topic),
        lst_topic[1],
        key_path
    )


def get_host_override(topic):
    """
    Override HOST if it set in key file
    """
    if topic in KeyMap.item_names:
        descr = KeyMap.item_names[topic]

        lst_host = descr.split(":")
        if len(lst_host) > 1:
            return lst_host[1]
        else:
            return KEYHOST

    return KEYHOST

def process_message(msg):
    """
    What to do with the message that's arrived.
    Looks up the topic in the KeyMap dictionary, and forwards
    the message onto Zabbix using the associated Zabbix key
    """
    topic = msg.topic
    payload = ensure_float(msg.payload.decode())
    logger.debug("Processing: " + topic)
    if topic in KeyMap.item_names:
        lld_update(topic)
        if payload == "ON":
            payload = "1"
        elif payload == "OFF":
            payload = "0"
        keyname = get_zabbix_item(topic)

        logger.debug("Payload type: " + str(type(payload)))
        logger.debug("Sending {} = {} to Zabbix to host {} key {}".format(
            topic, payload, get_host_override(topic), keyname
        ))
        # Zabbix can also accept text and character data...
        # should we sanitize input or just accept it as is?
        send_to_zabbix(
            [Metric(get_host_override(topic), keyname, payload)],
            ZBXSERVER,
            ZBXPORT
        )
    else:
        # Received something with a /raw/ topic,
        # but it didn't match anything. Log it, and discard it
        logger.debug("Unknown: {}".format(topic))


def cleanup(signum, frame):
    """
    Signal handler to ensure we disconnect cleanly
    in the event of a SIGTERM or SIGINT.
    """
    logger.info("Disconnecting from broker")
    # Publish a retained message to state that this client is offline
    mqttc.publish(PRESENCETOPIC, "0", retain=True)
    mqttc.disconnect()
    logger.info("Exiting on signal %d", signum)
    sys.exit(signum)


def connect():
    """
    Connect to the broker, define the callbacks, and subscribe
    This will also set the Last Will and Testament (LWT)
    The LWT will be published in the event of an unclean or
    unexpected disconnection.
    """
    logger.debug("Connecting to %s:%s", MQTT_HOST, MQTT_PORT)
    # Set the Last Will and Testament (LWT) *before* connecting
    mqttc.will_set(PRESENCETOPIC, "0", qos=0, retain=True)
    mqttc.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    result = mqttc.connect(MQTT_HOST, MQTT_PORT, 60)
    if result != 0:
        logger.error("Connection failed with error code %s. Retrying", result)
        time.sleep(10)
        connect()

    # Define the callbacks
    mqttc.on_connect = on_connect
    mqttc.on_disconnect = on_disconnect
    mqttc.on_publish = on_publish
    mqttc.on_subscribe = on_subscribe
    mqttc.on_unsubscribe = on_unsubscribe
    mqttc.on_message = on_message
    if DEBUG:
        mqttc.on_log = on_log


class KeyMap:
    """
    Read the topics and keys into a dictionary for internal lookups
    """
    items_by_host = None
    item_names = None

    @classmethod
    def load_map(cls, keyfile, keyhost):
        if cls.items_by_host is None or cls.item_names is None:
            cls.keyfile = keyfile
            cls.keyhost = keyhost
            cls.items_by_host = {}
            cls.item_names = {}
            cls._load_map()

    @classmethod
    def _load_map(cls):
        logger.debug("Loading map")
        with open(cls.keyfile, mode="r") as inputfile:
            reader = csv.reader(inputfile)
            cls.item_names = dict((rows[0], rows[1]) for rows in reader)
        cls._make_items_by_host()

    @classmethod
    def _make_items_by_host(cls):
        for key, value in cls.item_names.items():
            host = cls.keyhost
            host = get_host_override(key)  # This function should be defined somewhere in your code
            if host in cls.items_by_host:
                cls.items_by_host[host][key] = value
            else:
                cls.items_by_host[host] = {key: value}

# Use the signal module to handle signals
signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

# load
KeyMap.load_map(KEYFILE, KEYHOST)

# Connect to the broker
connect()

# Try to loop_forever until interrupted
try:
    mqttc.loop_forever()
except KeyboardInterrupt:
    logger.info("Interrupted by keypress")
    sys.exit(0)
