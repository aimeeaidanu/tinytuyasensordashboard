# TinyTuya API Server
# -*- coding: utf-8 -*-

# Modules
from __future__ import print_function
import threading
import time
import logging
import json
import socket
import datetime

import os
from flask import Flask

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

cred = credentials.Certificate('onehealth-ac6a5-firebase-adminsdk-8u9wm-e5ca423351.json')

app = firebase_admin.initialize_app(cred)

db = firestore.client()

try:
    import requests
except ImportError as impErr:
    print("WARN: Unable to import requests library, Cloud functions will not work.")
    print("WARN: Check dependencies. See https://github.com/jasonacox/tinytuya/issues/377")
    print("WARN: Error: {}.".format(impErr.args[0]))
try:
    import resource
except ModuleNotFoundError:
    print("Module 'resource' is not available on this system.")
import sys
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from socketserver import ThreadingMixIn 

# Terminal color capability for all platforms
try:
    from colorama import init
    init()
except:
    pass

import tinytuya

BUILD = "t10"

# Defaults
APIPORT = 8888
DEBUGMODE = False
DEVICEFILE = tinytuya.DEVICEFILE
SNAPSHOTFILE = tinytuya.SNAPSHOTFILE
CONFIGFILE = tinytuya.CONFIGFILE
TCPTIMEOUT = tinytuya.TCPTIMEOUT    # Seconds to wait for socket open for scanning
TCPPORT = tinytuya.TCPPORT          # Tuya TCP Local Port
MAXCOUNT = tinytuya.MAXCOUNT        # How many tries before stopping
UDPPORT = tinytuya.UDPPORT          # Tuya 3.1 UDP Port
UDPPORTS = tinytuya.UDPPORTS        # Tuya 3.3 encrypted UDP Port
UDPPORTAPP = tinytuya.UDPPORTAPP    # Tuya App
TIMEOUT = tinytuya.TIMEOUT          # Socket Timeout
RETRYTIME = 30
RETRYCOUNT = 5
SAVEDEVICEFILE = True

# Check for Environmental Overrides
debugmode = os.getenv("DEBUG", "no")
if debugmode.lower() == "yes":
    DEBUGMODE = True

# Logging
log = logging.getLogger(__name__)
if len(sys.argv) > 1 and sys.argv[1].startswith("-d"):
    DEBUGMODE = True
if DEBUGMODE:
    logging.basicConfig(
        format="\x1b[31;1m%(levelname)s [%(asctime)s]:%(message)s\x1b[0m", level=logging.DEBUG, 
        datefmt='%d/%b/%y %H:%M:%S'
    )
    log.setLevel(logging.DEBUG)
    log.debug("TinyTuya Server [%s]", BUILD)
    tinytuya.set_debug(True)

# Static Assets
web_root = os.path.join(os.path.dirname(__file__), "web")

# Global Stats
serverstats = {}
serverstats['tinytuya'] = "%s%s" % (tinytuya.version, BUILD)
serverstats['gets'] = 0
serverstats['errors'] = 0
serverstats['timeout'] = 0
serverstats['api'] = {}
serverstats['ts'] = int(time.time())         # Timestamp for Now
serverstats['start'] = int(time.time())      # Timestamp for Start 

# Global Variables
running = True
tuyadevices = []
deviceslist = {}
newdevices = []
retrydevices = {}
retrytimer = 0
cloudconfig = {'apiKey':'', 'apiSecret':'', 'apiRegion':'', 'apiDeviceID':''}


# Terminal formatting
(bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(True)

# Helpful Functions

def tuyaLookup(deviceid):
    #  Function to Lookup Tuya device info by (id) returning (name, key)
    for i in tuyadevices:
        if i["id"] == deviceid:
            if "mac" in i:
                return (i["name"], i["key"], i["mac"])
            else:
                return (i["name"], i["key"], "")
    return ("", "", "")

def appenddevice(newdevice, devices):
    if newdevice["id"] in devices:
        return True
    devices[newdevice["id"]] = newdevice
    return False

def offlineDevices():
    # return undiscovered devices
    offline={}
    for d in tuyadevices:
        if type(d) != dict:
            continue
        id = d["id"]
        if id not in deviceslist:
            offline[id] = {}
            offline[id]["name"] = d["name"] 
            if "mac" in d:
                offline[id]["mac"] = d["mac"]
    return offline

def formatreturn(value):
    if value is None:
        result = {"status": "OK"}
    elif type(value) is dict:
        result = value
    else:
        result = {"status": value}
    return(json.dumps(result))

def get_static(web_root, fpath):
    if fpath.split('?')[0] == "/":
        fpath = "index.html"
    if fpath.startswith("/"):
        fpath = fpath[1:]
    fpath = fpath.split("?")[0]
    freq = os.path.join(web_root, fpath)
    if os.path.exists(freq):
        if freq.lower().endswith(".js"):
            ftype = "application/javascript"
        elif freq.lower().endswith(".css"):
            ftype = "text/css"
        elif freq.lower().endswith(".png"):
            ftype = "image/png"
        elif freq.lower().endswith(".html"):
            ftype = "text/html"
        else:
            ftype = "text/plain"

        with open(freq, 'rb') as f:
            return f.read(), ftype

    return None, None

def tuyaLoadJson():
    # Check to see if we have additional Device info
    tdevices = []
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tdevices = json.load(f)
        log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tdevices))
    except:
        # No Device info
        log.debug("Device file %s could not be loaded", DEVICEFILE)

    return tdevices

def tuyaSaveJson():
    if not SAVEDEVICEFILE:
        return False

    try:
        with open(DEVICEFILE, 'w') as f:
            json.dump(tuyadevices, f, indent=4)
        log.debug("saved=%s [%d devices]", DEVICEFILE, len(tuyadevices))
    except:
        return False

    return True

def tuyaLoadConfig():
    # Check to see if we have Cloud account credentials from wizard
    config = {'apiKey':'v3kp5jgx87thsh479uqe', 'apiSecret':'53b9189795c14321a7852000d905509e', 'apiRegion':'us', 'apiDeviceID':'eb02f89c465dccc56cr3pr'}
    try:
        # Load defaults
        with open(CONFIGFILE) as f:
            config = json.load(f)
        log.debug("loaded config=%s", CONFIGFILE)
    except:
        # No Device info
        log.debug("No cloud config file found %s", CONFIGFILE)

    return config

tuyadevices = tuyaLoadJson()
cloudconfig = tuyaLoadConfig()

def tuyaCloudRefresh():
    log.debug("Calling Cloud Refresh")
    if cloudconfig['apiKey'] == '' or cloudconfig['apiSecret'] == '' or cloudconfig['apiRegion'] == '' or cloudconfig['apiDeviceID'] == '':
        log.debug("Cloud API config missing, not loading")
        return {'Error': 'Cloud API config missing'}

    global tuyadevices
    cloud = tinytuya.Cloud( **cloudconfig )
    # on auth error, getdevices() will implode
    if cloud.error:
        return cloud.error
    tuyadevices = cloud.getdevices(False)
    tuyaSaveJson()
    return {'devices': tuyadevices}

def getDeviceIdByName(name):
    id = False
    nameuq = urllib.parse.unquote(name)
    for key in deviceslist:
        if deviceslist[key]['name'] == nameuq:
            id = deviceslist[key]['id']
            break
    return (id)

# Threads
def tuyalisten(port):
    """
    Thread to listen for Tuya devices UDP broadcast on port 
    """
    log.debug("Started tuyalisten thread on %d", port)
    print(" - tuyalisten %d Running" % port)

    # Enable UDP listening broadcasting mode on UDP port 
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        # SO_REUSEPORT not available
        pass
    client.bind(("", port))
    client.settimeout(5)

    while(running):
        try:
            data, addr = client.recvfrom(4048)
        except (KeyboardInterrupt, SystemExit) as err:
            break
        except Exception as err:
            continue
        ip = addr[0]
        gwId = dname = dkey = mac = ""
        result = data
        try:
            result = tinytuya.decrypt_udp( data )
            result = json.loads(result)
            #log.debug("Received valid UDP packet: %r", result)
            ip = result["ip"]
            gwId = result["gwId"]
        except:
            result = {"ip": ip}
            #log.debug("Invalid UDP Packet: %r", result)
        try:
            # Try to pull name and key data
            (dname, dkey, mac) = tuyaLookup(gwId)
        except:
            pass
        # set values
        result["name"] = dname
        result["mac"] = mac
        result["key"] = dkey
        result["id"] = gwId

        # add device if new
        if not appenddevice(result, deviceslist):
            # Added device to list
            if dname == "" and dkey == "" and result["id"] not in newdevices:
                # If fetching the key failed, save it to retry later
                retrydevices[result["id"]] = RETRYCOUNT
                newdevices.append(result["id"])
    print(' - tuyalisten', port, 'Exit')
    log.debug("tuyalisten server thread on %d stopped", port)

def automaticdatafetch(port):
    print(" - automaticdatafetch %d Running" % port)
    log.debug("Started automaticdatafetch thread on %d", port)
    while True:
        current_time = datetime.datetime.now()
        time_to_sleep = (datetime.timedelta(hours=1) - datetime.timedelta(minutes=current_time.minute, seconds=current_time.second)).total_seconds()
        print(f"Sleeping for {time_to_sleep:.2f} seconds until next hour.")
        time.sleep(time_to_sleep)
        print("Waking up to fetch logs...")
        get_and_upload_logs()


def keepAliveTest(port):
    print(" - keepAliveTest %d Running" % port)
    log.debug("Started keepAliveTest thread on %d", port)
    while True:
        print("Keep alive test...")
        time.sleep(60)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    pass

def delayoff(d, sw):
    d.turn_off(switch=sw, nowait=True)
    d.close()

class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if DEBUGMODE:
            sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))
        else:
            pass

    def address_string(self):
        # replace function to avoid lookup delays
        host, hostport = self.client_address[:2]
        return host

    def do_POST(self):
        self.send_response(200)
        message = "Error"
        contenttype = 'application/json'
        # Send headers and payload  
        self.send_header('Content-type',contenttype)
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

    def do_GET(self):
        global retrytimer, retrydevices
        global cloudconfig, deviceslist

        self.send_response(200)
        message = "Error"
        contenttype = 'application/json'
        if self.path == '/devices':
            c = tinytuya.Cloud( apiRegion="us", apiKey=cloudconfig["apiKey"], 
                                apiSecret=cloudconfig["apiSecret"] )
            devices = c.getdevices()
            message = json.dumps(devices)
        elif self.path == '/help':
            # show available commands
            cmds = [("/devices","List all devices discovered with metadata"),
                    ("/device/{DeviceID}|{DeviceName}", "List specific device metadata"),
                    ("/numdevices", "List current number of devices discovered"),
                    ("/status/{DeviceID}|{DeviceName}", "List current device status"),
                    ("/set/{DeviceID}|{DeviceName}/{Key}|{Code}/{Value}", "Set DPS {Key} or {Code} with {Value}"),
                    ("/turnon/{DeviceID}|{DeviceName}/{SwitchNo}", "Turn on device, optional {SwtichNo}"),
                    ("/turnoff/{DeviceID}|{DeviceName}/{SwitchNo}", "Turn off device, optional {SwtichNo}"),
                    ("/delayoff/{DeviceID}|{DeviceName}/{SwitchNo}/{Time}", "Turn off device with delay of 10 secs, optional {SwitchNo}/{Time}"),
                    ("/sync", "Fetches the device list and local keys from the Tuya Cloud API"),
                    ("/cloudconfig/{apiKey}/{apiSecret}/{apiRegion}/{apiDeviceID}", "Sets the Tuya Cloud API login info"),
                    ("/offline", "List of registered devices that are offline")]
            message = json.dumps(cmds)
        elif self.path == '/stats':
            # Give Internal Stats
            serverstats['ts'] = int(time.time())
            serverstats['mem'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            message = json.dumps(serverstats)
        elif self.path.startswith('/set/'):
            try:
                # ['', 'set', 'deviceid', 'key', 'value']
                (ignore1, ignore2, id, dpsKey, dpsValue) = self.path.split('/')
                # convert to correct types
                dpsValue = urllib.parse.unquote(dpsValue)
                if dpsValue.lower() == "true":
                    dpsValue = True
                elif dpsValue.lower() == "false":
                    dpsValue = False
                elif dpsValue.startswith('"'):
                    dpsValue = dpsValue.split('"')[1]
                elif dpsValue.isnumeric():
                    dpsValue = int(dpsValue)
                if(id not in deviceslist):
                    id = getDeviceIdByName(id)
                if not dpsKey.isnumeric():
                    for x in tuyadevices:
                        if x['id'] == id:
                            if 'mapping' in x:
                                for i in x['mapping']:
                                    if x['mapping'][i]['code'] == str(dpsKey):
                                        dpsKey = i
                                        break
                log.debug("Set dpsKey: %s dpsValue: %s" % (dpsKey,dpsValue))
                if(id in deviceslist):
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.set_value(dpsKey,dpsValue,nowait=True))
                    d.close()
                else:
                    message = json.dumps({"Error": "Device ID not found.", "id": id})
                    log.debug("Device ID not found: %s" % id)
            except:
                message = json.dumps({"Error": "Syntax error in set command URL.", "url": self.path})
                log.debug("Syntax error in set command URL: %s" % self.path)
        elif self.path.startswith('/device/'):
            id = self.path.split('/device/')[1]
            c = tinytuya.Cloud( apiRegion="us", apiKey=cloudconfig["apiKey"], 
                                apiSecret=cloudconfig["apiSecret"] )
            devices = c.getdevices()
            theDevice = next((device for device in devices if device['id'] == id), None)
            message = json.dumps(theDevice)
        elif self.path.startswith('/turnoff/'):
            id = self.path.split('/turnoff/')[1]
            sw = 1
            if "/" in id:
                try:
                    (id, sw) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in turnoff command.", "url": self.path})
                    log.debug("Syntax error in in turnoff command: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.turn_off(switch=sw, nowait=True))
                    d.close()
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device: %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})      
                log.debug("Device ID not found: %s" % id)      
        elif self.path.startswith('/delayoff/'):
            id = self.path.split('/delayoff/')[1]
            sw = 1
            delay = 10
            if "/" in id:
                try:
                    (id, sw, delay) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in delayoff command.", "url": self.path})
                    log.debug("Syntax error in in delayoff command: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))

                    timer = threading.Timer(int(delay), delayoff, args = (d, sw))
                    timer.start()

                    message = json.dumps({"OK": "Turning of in %s seconds." % (delay), "url": self.path})
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})
                log.debug("Device ID not found: %s" % id)
        elif self.path.startswith('/turnon/'):
            id = self.path.split('/turnon/')[1]
            sw = 1
            if "/" in id:
                try:
                    (id, sw) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in turnon command.", "url": self.path})
                    log.debug("Syntax error in turnon command URL: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.turn_on(switch=sw, nowait=True))
                    d.close()
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})     
                log.debug("Device ID not found: %s" % id)        
        elif self.path == '/numdevices':
            jout = {}
            c = tinytuya.Cloud( apiRegion="us", apiKey=cloudconfig["apiKey"], 
                                apiSecret=cloudconfig["apiSecret"] )
            devices = c.getdevices()
            jout["found"] = len(devices)
            jout["registered"] = len(devices)
            message = json.dumps(jout)
        elif self.path.startswith('/status/'):
            id = self.path.split('/status/')[1]
            c = tinytuya.Cloud( apiRegion="us", apiKey=cloudconfig["apiKey"], 
                                apiSecret=cloudconfig["apiSecret"] )
            try:
                result = c.getstatus(id)
                print(result)
                transformed_result = {
                    "dps": {item["code"]: item["value"] for item in result["result"]},
                    "dps_mapping": []
                }
                message = json.dumps(transformed_result)
            except:
                message = json.dumps({"Error": "Error polling device.", "id": id})
                log.debug("Error polling device %s" % id)
        elif self.path == '/sync':
            message = json.dumps(tuyaCloudRefresh())
            retrytimer = time.time() + RETRYTIME
            retrydevices['*'] = 1
        elif self.path.startswith('/cloudconfig/'):
            cfgstr = self.path.split('/cloudconfig/')[1]
            cfg = cfgstr.split('/')
            if len(cfg) != 4:
                message = json.dumps({"Error": "Syntax error in cloud config command URL."})
                log.debug("Syntax error in cloud config command URL %s" % self.path)
            else:
                cloudconfig['apiKey'] = cfg[0]
                cloudconfig['apiSecret'] = cfg[1]
                cloudconfig['apiRegion'] = cfg[2]
                cloudconfig['apiDeviceID'] = cfg[3]
                message = json.dumps(tuyaCloudRefresh())
                retrytimer = time.time() + RETRYTIME
                retrydevices['*'] = 1
        elif self.path == '/offline':
            message = json.dumps(offlineDevices())
        elif self.path.startswith('/getlogs/'):
            try:
                print("gettinglogs")
                defaultStartingTimestamp = 1711436400

                path_parts = self.path.split('/getlogs/')[1].split('/')
                device_id = path_parts[0]
                dateAtTimeOfRequest = int(time.time())
                current_date = datetime.datetime.now().strftime('%m-%Y')
                doc_ref = db.collection('sensors').document(device_id).collection('data').document(current_date)

                # Get all collections in the document
                collections = doc_ref.collections()
                fetchedData = {}

                for collection in collections:
                    values_doc_ref = collection.document('values')

                    values_doc = values_doc_ref.get()

                    if values_doc.exists:
                        collectionData = values_doc.to_dict()
                        print(f"Data in '{collection.id}' collection: {collectionData}")

                        current_timestamp = int(time.time())
                        latest_timestamp = int(max(collectionData['data'].keys()))

                        print(f"Current: {current_timestamp} Latest: {latest_timestamp} Diff: {current_timestamp - latest_timestamp} DiffAllowed: {int(current_timestamp - latest_timestamp) > 300}")

                        fetchedData[collection.id] = {
                            'data': collectionData['data'],
                            'timestamp': latest_timestamp,
                            'nextTimestamp': latest_timestamp + 300,
                        }
                    else:
                        print(f"No 'values' document found in '{collection.id}' collection.")
                    
                    print("\n")

                message = json.dumps(fetchedData)
            except Exception as e:
                log.error(f"Error processing getlogs request: {e}")
                message = json.dumps({"error": "Invalid request parameters or internal error"})
                
        else:
            # Serve static assets from web root first, if found.
            fcontent, ftype = get_static(web_root, self.path)
            if fcontent:
                self.send_header('Content-type','{}'.format(ftype))
                self.send_header('Content-Length', str(len(fcontent)))
                self.end_headers()
                self.wfile.write(fcontent)
                return

        # Counts 
        if "Error" in message:
            serverstats['errors'] = serverstats['errors'] + 1
        serverstats['gets'] = serverstats['gets'] + 1

        # Send headers and payload
        self.send_header('Content-type',contenttype)
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

def api(port):
    """
    API Server - Thread to listen for commands on port 
    """
    log.debug("Started api server thread on %d", port)
    print(" - api %d Running" % port)

    with ThreadingHTTPServer(('', port), handler) as server:
        try:
            # server.serve_forever()
            while running:
                server.handle_request()
        except:
            print(' CANCEL \n')
    print(' - api', port, 'Exit')
    log.debug("API server thread on %d stopped", port)


def get_and_upload_logs():
    current_hour = datetime.datetime.now().hour
    start_time_orig = datetime.datetime.now().replace(minute=0, second=0, microsecond=0) - datetime.timedelta(hours=1)
    end_time_orig = start_time_orig + datetime.timedelta(hours=1)
    start_time = int(time.mktime(start_time_orig.timetuple()))
    end_time = int(time.mktime(end_time_orig.timetuple()))

    print(f"Starting log retrieval and upload for hour: {current_hour} (from {start_time} to {end_time})")

    c = tinytuya.Cloud( apiRegion="us", apiKey="v3kp5jgx87thsh479uqe", 
                        apiSecret="53b9189795c14321a7852000d905509e" )
    devices = c.getdevices()
    print(f"Devices: {devices}")
    for device in devices:
        print(f"DEVICEDEVICEDEVICE: {device}")
        device_id = device['id']

        try:
            print("Attempting to get logs for device: " + device_id)
            logs = c.getdevicelog(device_id, start_time, end_time)
            try:
                data_to_save = {}
                last_times = {
                    'temp_current': 0,
                    'humidity_value': 0,
                    'voc_value': 0,
                    'co2_value': 0,
                    'ch2o_value': 0,
                    'pm25_value': 0
                }

                for onelog in reversed(logs.get('result', {}).get('logs', [])):
                    code = onelog.get('code')
                    if code in ['temp_current', 'humidity_value', 'voc_value', 'co2_value', 'ch2o_value', 'pm25_value']:
                        event_time = int(onelog.get('event_time')/1000)
                        value = str(onelog.get('value'))
                        if code and str(event_time) and value:
                            if code not in data_to_save:
                                data_to_save[code] = {}

                            if event_time - last_times[code] > 300:
                                data_to_save[code][str(event_time)] = value
                                last_times[code] = event_time
                
                for code, data in data_to_save.items():
                    try:
                        doc_ref = db.collection('sensors').document(device_id).collection('data').document(datetime.datetime.now().strftime('%m-%Y')).collection(code).document('values')
                        print(f"Saving {code} data to Firestore: {data} for {device_id}")
                        doc_ref.set({'data': data}, merge=True)
                    except Exception as e:
                        print(f"Error saving {code} data to Firestore: {e}")
                        raise

            except Exception as e:
                log.error(f"Error saving device logs for {device_id}: {e}")
        except Exception as e:
            log.error(f"Error retrieving device logs for {device_id}: {e}")
            message = json.dumps({"error": "Failed to retrieve device logs"})

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

# MAIN Thread
if __name__ == "__main__":
    # creating thread
    tuyaUDP = threading.Thread(target=tuyalisten, args=(UDPPORT,))
    tuyaUDPs = threading.Thread(target=tuyalisten, args=(UDPPORTS,))
    tuyaUDP7 = threading.Thread(target=tuyalisten, args=(UDPPORTAPP,))
    keepalive = threading.Thread(target=keepAliveTest, args=(7002,))
    autodatafetch = threading.Thread(target=automaticdatafetch, args=(7001,))
    apiServer = threading.Thread(target=api, args=(APIPORT,))
    
    print(
        "\n%sTinyTuya %s(Server)%s [%s%s]\n"
        % (bold, normal, dim, tinytuya.__version__, BUILD)
    )
    if len(tuyadevices) > 0:
        print("%s[Loaded devices.json - %d devices]%s\n" % (dim, len(tuyadevices), normal))
    else:
        print("%sWARNING: No devices.json found - limited functionality.%s\n" % (alertdim,normal))

    # start threads
    print("Starting threads...")
    log.debug("Starting threads")
    tuyaUDP.start()
    tuyaUDPs.start()
    tuyaUDP7.start()
    keepalive.start()
    autodatafetch.start()
    apiServer.start()

    print(" * API and UI Endpoint on http://localhost:%d" % APIPORT)
    log.debug("Server URL http://localhost:%d" % APIPORT)
    
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
    try:
        while(True):
            log.debug("Discovered Devices: %d   " % len(deviceslist))

            if retrytimer <= time.time() or '*' in retrydevices:
                if len(retrydevices) > 0:
                    # only refresh the cloud if we are not here because /sync was called
                    if '*' not in retrydevices:
                        tuyaCloudRefresh()
                        retrytimer = time.time() + RETRYTIME
                    found = []
                    # Try all unknown devices, even if the retry count expired
                    for devid in newdevices:
                        dname = dkey = mac = ""
                        try:
                            (dname, dkey, mac) = tuyaLookup(devid)
                        except:
                            pass

                        if dname != "" or dkey != "":
                            #print('found!', devid, dname, dkey)
                            deviceslist[devid]['name'] = dname
                            deviceslist[devid]['key'] = dkey
                            deviceslist[devid]['mac'] = mac
                            found.append(devid)
                            if devid in retrydevices:
                                del retrydevices[devid]
                    for devid in found:
                        newdevices.remove(devid)

                    # Decrement retry count
                    expired = []
                    for devid in retrydevices:
                        retrydevices[devid] -= 1
                        if retrydevices[devid] < 1:
                            expired.append(devid)
                    for devid in expired:
                        del retrydevices[devid]
            time.sleep(2)
        
    except (KeyboardInterrupt, SystemExit):
        running = False
        # Close down API thread
        print("Stopping threads...")
        log.debug("Stoppping threads")
        requests.get('http://localhost:%d/stop' % APIPORT)