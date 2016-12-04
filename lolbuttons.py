#!/usr/bin/env python3
from scapy.all import *
import pywemo

dashes = { '44:65:0d:74:58:31': 'whiskas' }

def findDash(pkts):
    for pkt in pkts:
        if pkt.fields['src'] in dashes:
            print("Dash %s was pressed" % dashes[pkt.fields['src']])
            triggerDash(dashes[pkt.fields['src']])

def toggleLights(lights):
    for light in lights:
        print("Toggling: %s" % lights[light].name)
        lights[light].toggle()

def triggerDash(dashName):
    # switch case match the dashes here
    if dashName == 'whiskas':
        toggleLights(bridge.Lights)

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