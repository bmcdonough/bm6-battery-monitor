# bm6-battery-monitor
Read data from BM6 BLE battery monitors without the invasive app.

# Python application
```
usage: bm6-battery-monitor.py [-h] [--format {ascii,json}] (--address <address> | --scan)

bm6-battery-monitor.py --scan
Address           RSSI
50:54:7B:xx:xx:xx -83

bm6-battery-monitor.py --address 50:54:7B:xx:xx:xx
Voltage: 11.93v
Temperature: 24C
SoC: 76%

bm6-battery-monitor.py --address 50:54:7B:xx:xx:xx --format=json
{"voltage": 11.93, "temperature": 24, "soc": 76}
```
Tested on a Linux VM with a USB Bluetooth dongle and a Windows laptop with built in Bluetooth. Have not tested this on MacOS but in theory it should work. 

Linux testing environment:
- Ubuntu 22.04
- Python 3.10.12
- bleak 0.22.2
- pycryptodome 3.20.0

Windows testing environment:
- Windows 11
- Python 3.12.5
- bleak 0.22.2
- pycryptodome 3.20.0

# ESPHome
Under the ESPHome directory you can find a configuration that will allow you to read your BM6 battery monitor using an ESP32 and ESPHome. This was tested on ESPHome 2024.8.0 and may break at any time...

# Reverse Engineering
For details on how I reverse engineered this, see the below post:  
https://www.tarball.ca/posts/reverse-engineering-the-bm6-ble-battery-monitor/

# Other Names
The following product is a BM6 with a different name:  
Sealey Vehicle Finder & Battery Monitor Sensor BT2020 

# Credits
I wouldn't have been able to create this without the following resources:  
https://github.com/KrystianD/bm2-battery-monitor/blob/master/.docs/reverse_engineering.md  
https://doubleagent.net/bm2-reversing-the-ble-protocol-of-the-bm2-battery-monitor/  
https://www.youtube.com/watch?v=lhLff9VACU4  
mdande (https://www.github.com/mdande) for State of Charge (SoC) pull request
