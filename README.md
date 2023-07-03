# insta360-wifi-api

**Python scripts to talk to Insta360 action cameras using the WiFi API**

## Connecting to the WiFi

Fortunately enough it is possibile to connect a GNU/Linux PC to 
the Insta360 through the WiFi, the default passowrd of the 
camera internal access point is **88888888**.

Said incidentally, this is an **huge security hole** of the 
camera: as far I know it is not possibile to disable the WiFi 
interface or change the password (at least from the camera touch 
screen interface), so any host in the nearby can connect to your 
camera as soon it is turned on; once estabilished the connection 
you can also do a **telnet** into the Insta360's GNU/Linux 
operating system as **root** (the IP address of the camera is 
**192.168.42.1**) and do whaterver you want, even to damage 
permanently (brick) the camera.


More info here: [Insta360: WiFi protocol reverse engineering](https://www.rigacci.org/wiki/doku.php/doc/appunti/hardware/insta360_one_rs_wifi_reverse_engineering).
