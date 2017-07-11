#!/usr/bin/env python3

from scapy.all import *
import pywemo
import requests
import ujson

dashes = { '44:65:0d:74:58:31': 'whiskas', 'ac:63:be:48:c1:9e': 'durex' }

def findDash(pkts):
    for pkt in pkts:
        if pkt.fields['src'] in dashes:
            print("Dash %s was pressed" % dashes[pkt.fields['src']])
            triggerDash(dashes[pkt.fields['src']])

def triggerDash(dashName):
    # Do case matching on the dashes here

    if dashName == 'whiskas':
        toggleLights(bridge.Lights)
    elif dashName == 'durex':
        toggleCouch()

def toggleLights(lights):
    for light in lights:
        print("Toggling: %s" % lights[light].name)
        lights[light].toggle()

def toggleCouch():
    baseurl = 'https://api.spark.io/v1/devices/[REDACTED]/'
    token = '[REDACTED]'
    try:
        response = requests.get(baseurl + "status?access_token=" + token)
        response = ujson.loads(response.text)

        if response['result'] == "off":
            #url = baseurl + "on"
            url = baseurl + "setColour"
        else:
            url = baseurl + "off"

        data = {'access_token': token, "args": "#E9967A"}
        response = requests.post(url, data=data)
        print("Toggling Couch Lights")
    except:
        print("Invalid Response")

def main():

    print("Hunting for WeMo lights")
    devices = pywemo.discover_devices()
    global bridge
    bridge = next((x for x in devices if isinstance(x, pywemo.ouimeaux_device.bridge.Bridge)), None) # Find a WeMo Bridge Link
    if bridge is not None:
        print("Found WeMo Bridge with %s lights" % (len(bridge.Lights)))
    else:
        print("Error: Couldn't find a WeMo Bridge. Please try again")
        exit(1)

    while True:
        sniff(prn=findDash, filter="llc xid", store=0, count=1) # Dash seems to broadcast LLC XID before anything else. So it's a quicker trigger than ARP or DHCPv4

if __name__ == '__main__':
    main()