Internet Access Control Use TC for OpenWrt
===================================

This software is forked from k-szuster/luci-access-control.

k-szuster/luci-access-control allalows you to  restrict the internet access for specific hosts in your LAN.It based on iptables.

This software is based on tc,it limit the speed of client to deny the access to net work.Schedule is based on crontab.
After installation you'll find a new page in OpenWrt's GUI: Network/Access control.

Screen shot
-----------
![Internet Access Control](https://github.com/funTechCn/luci-access-control/blob/master/snapshot.png?raw=true)


To build the package OpenWrt 
-----------------------------------
The package works on any target (it is architecture independent).

Add 
src-git appAccessControl https://github.com/funTechCn/luci-access-control.git
to "feeds.conf.default"

- After this has been completed, call 
```
	./scripts/feeds update appAccessControl ; ./scripts/feeds install -a appAccessControl
```
from your openwrt folder. 

- Call
```
	make menuconfig
```
Here, you must include the following packages in your OpenWRT build for everything to work:
```
	LuCI -> applications -> luci-app-access-control
```
- Call make to compile OpenWRT with the selected package installed.
You'll find it in <openwrt>/bin/<target>/packages/luci/luci-app-access-control_....ipk file.


Note
this package is not finished,iptable mode is uncompelete
