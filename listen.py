#!/usr/bin/python2
# -*- coding: utf-8 -*-
import os
from scapy.all import sniff, ARP
from datetime import datetime, timedelta
import requests  # Use requests to trigger the ITTT webhook
from send_mail import send_mail  # This function sends mails directly
last_press = datetime.now() - timedelta(seconds=10)

interface = "ap0"
my_mac = "98:de:d0:aa:bb:cc"

# Button-List
#
# button_mac, button_name, button_event, button_email_to, rf433_command, rf433_state
#
wz = "00001"
wz_all = wz + " 1 " + wz + " 2 " + wz + " 3 " + wz + " 4"
buero = "00010"
buero_all = buero + " 1 " + buero + " 2 " + buero + " 3 " + buero + " 4"
kueche = "00011"
kueche_1plus4 = kueche + " 2 " + kueche + " 4"
all_all = wz_all + " " + buero_all + " " + kueche_1plus4

buttons = [
["50:f5:da:aa:bb:c1", "Wilkinson", "", "", wz_all, "0"],
["50:f5:da:aa:bb:c2", "Kleenex", "", "", kueche_1plus4, "0"],
["50:f5:da:aa:bb:c3", "Ariel", "", "", all_all, "0"]
]

rf433_cmd = "/home/pi/raspberry-remote/send -s"
rf433_toggle = "0"

def arp_received(packet):
    global last_press
    if packet[ARP].hwsrc != my_mac:  # If it is not the MAC of the WiFi stick ap0 it could be another button
        if packet[ARP].op == 1 and packet[ARP].hwdst == '00:00:00:00:00:00':
            global found
            found = 0
            for mac_entry in buttons:
                button_mac = str(mac_entry[0:1]).strip('[\']')
                if packet[ARP].hwsrc == button_mac:  # This is the MAC of the first dash button
                    found = 1
                    now = datetime.now()
                    if last_press + timedelta(seconds=5) <= now:
                        button_name = str(mac_entry[1:2]).strip('[\']')
                        print("" + str(now) + " - " + button_name + " Button pressed (" + packet[ARP].hwsrc + ") !")
                        last_press = now
                        button_event = str(mac_entry[2:3]).strip('[\']')
                        button_email_to = str(mac_entry[3:4]).strip('[\']')
                        button_rf433_cmd = str(mac_entry[4:5]).strip('[\']')
                        button_rf433_toggle = str(mac_entry[5:]).strip('[\']')
                        if button_event:
                            requests.get("https://maker.ifttt.com/trigger/dash_" + button_event + "/with/key/bL8bUswvgRQ-mo3qmZqUr6")
                        if button_email_to:
                            send_mail(button_email_to, subject="" + button_name + " Dash Button gedrückt",
                                text="Hallo,\n\nder " + button_name + " Dash-Button mit der MAC-Adresse " + packet[ARP].hwsrc + " wurde " + str(now) + " gedrückt.\n\nViele Grüße,\nDein Raspi")
                        if button_rf433_cmd:
                            global rf433_toggle
                            rf433_toggle = button_rf433_toggle
                            print("  switch " + button_rf433_cmd + " to stat " + rf433_toggle)
                            os.system(rf433_cmd + " " + button_rf433_cmd + " " + rf433_toggle)
#                            exec(rf433_cmd + " " + button_rf433_cmd + " " + rf433_toggle + " 2>&1 > /dev/null")
                            if rf433_toggle == "1":
                                rf433_toggle = "0"
                            else:
                                rf433_toggle = "1"
                            mac_entry[5] = rf433_toggle
                        break
        if found == 0:
                print("Unknown Device connecting: " + packet[ARP].hwsrc)


if __name__ == "__main__":
    print("Listening for ARP packets " + interface + " ...")
    sniff(prn=arp_received, iface=interface, filter="arp", store=0, count=0)
