# Wireless security using Raspberry PI 4, Kismet and Aircrack-ng

Everything is connected to wireless these days; In my case I found that I have LOTS of devices after running a simple [nmap command on my home network](https://www.freecodecamp.org/news/enhance-nmap-with-python/#nmap-101-identify-all-the-public-services-in-our-network):

```shell=
[josevnz@dmaf5 ~]$ sudo nmap -v -n -p- -sT -sV -O --osscan-limit --max-os-tries 1 -oX $HOME/home_scan.xml 192.168.1.0/24
```

So I started to wonder?
* Is my wireless network secure?
* How long would it take to an attacker to get in?

I have a Raspberry 4 with Ubutu installed and decided to use the well know [Aircrack-ng](https://aircrack-ng.org/index.html) to find out.

In this article you will learn:

* How to install and setup Aircrack-ng
* How to get a whole picture of the networks nearby you
* How to capture the handshake of your own network and how you infiltrate it

# Note: The saying 'Ask for forgiveness, not permission' doesn't apply here

And by that I mean that you should not be trying to evasdrop or infiltrate at wireless network that is not yours. It is relatively easy to detect if a new unknow client joined your wireless network, also it is illegal.

So do the right thing, use this tutorial to learn and not to break into someone elses network, OK?

# Getting to know your hardware

I will jump a little bit ahead to show you a small issue with the Raspberry 4 integrated Wireless interface.

__The Raspberry PI 4 onboard wireless card will not work out of the box as the firmware doesn't support monitor mode__

If you run airmon-ng you will get the following error:

```shell=
josevnz@raspberrypi:~$ sudo airmon-ng start wlan0


PHY	Interface	Driver		Chipset

phy0	wlan0		brcmfmac	Broadcom 43430


ERROR adding monitor mode interface: command failed: Operation not supported (-95)

```

There are works to [support this](https://github.com/seemoo-lab/bcm-rpi3), but you are also risking bricking your hardware. Instead I took the easy way out and ordered an external Wifi dungle from [CanaKit](https://www.canakit.com/raspberry-pi-wifi.html).

The CanaKit wireless card worked out of the box, will see it shortly. But first let's install and play with our first tool


## Making sure the interface is setup in monitor mode

By default the network interface will have the monitor mode off:
```shell=
root@raspberrypi:~# iwconfig wlan1
wlan1     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=0 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off

```

I know I will always set up my 'Ralink Technology, Corp. RT5370 Wireless Adapter' adapter in monitor mode, but I need to be careful as Ubuntu can swap wlan0 and wlan1 (The Broadcom adapter I want to skip).

The Ralink adapter is a usb adapter, so we can find out where it it:

```shell=
josevnz@raspberrypi:/etc/netplan$ /bin/lsusb|grep Ralink
Bus 001 Device 004: ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter
```

Now we need to find out what device was mapped to the Ralink adapter; With a little bit of help of the Ubuntu community I found than the Ralink adapter uses the *rt2800usb driver* [5370 Ralink Technology](https://help.ubuntu.com/community/WifiDocs/Device/Ralink_RT5370)

The answer I seek is here:

```shell=
josevnz@raspberrypi:~$ ls /sys/bus/usb/drivers/rt2800usb/*:1.0/net/
wlan1
```

So my final script looks like this:

```shell=
root@raspberrypi:~#/bin/cat<<RC_LOCAL>/etc/rc.local
#!/bin/bash
usb_driver=rt2800usb
wlan=\$(/bin/ls /sys/bus/usb/drivers/\$usb_driver/*/net/)
if [ $? -eq 0 ]; then
        set -ex
        /usr/sbin/ifconfig "\$wlan" down
        /usr/sbin/iwconfig "\$wlan" mode monitor
        /usr/sbin/ifconfig "\$wlan" up
        set +ex
fi
RC_LOCAL
root@raspberrypi:~# chmod u+x /etc/rc.local && shutdown -r now "Enabling monitor mode"
```

Make sure the card is on monitor mode:

```shell=
root@raspberrypi:~# iwconfig wlan1
iw        iwconfig  iwevent   iwgetid   iwlist    iwpriv    iwspy     
root@raspberrypi:~# iwconfig wlan1
wlan1     IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz  Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```

Good, let's move on with the tool setup


# Kismet

[Kismet](https://www.kismetwireless.net/) is:

> Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.

## Kistmet installation and setup

The version that comes with the Ubuntu RaspberryPI by default is from 2016, *way too old*.

Instead, get an updated binary as explained [I have Ubuntu focal, check with ```lsb_release --all```](https://www.chelseapiersct.com/fitness/open-workout/):

```shell=
wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | sudo apt-key add -
echo 'deb https://www.kismetwireless.net/repos/apt/release/focal focal main' | sudo tee /etc/apt/sources.list.d/kismet.list
sudo apt update
sudo apt install kismet
```

Kismet need elevated privileges to run. And deals with possibly hostile data. So runing with minimized permissions is the safest approach. The right way to setup is by using a Unix group and suid binary. My user is 'josevnz' so I did this:

```shell=
sudo apt-get install kismet
sudo usermod --append --groups kismet josevnz
```


Then I overrode the default configuration with the following parameters:

### /etc/kismet/kismet_logging.conf

Save my logs to a SSD drive dedicated for this purpouse

```
logprefix=/data/kismet
```

### /etc/kismet/kismet_httpd.conf

I will enable SSL for my Kistmet [installation by using a self signed certificate](https://github.com/josevnz/home_nmap/tree/main/tutorial). I will use for that the Cloudflare CFSSL tools:

```shell=
sudo apt-get update -y
sudo apt-get install -y golang-cfssl
```

Next step is to create the self-signed certificates. There is a lot of boilerplate steps here, so I will show you how you can jump through them (but please read the man pages to see what each command do):

#### Initial certificate
```shell=
sudo /bin/mkdir --parents /etc/pki/raspberrypi
sudo /bin/cat<<CA>/etc/pki/raspberrypi/ca.json
{
   "CN": "Nunez Barrios family Root CA",
   "key": {
     "algo": "rsa",
     "size": 2048
   },
   "names": [
   {
     "C": "US",
     "L": "CT",
     "O": "Nunez Barrios",
     "OU": "Nunez Barrios Root CA",
     "ST": "United States"
   }
  ]
}
CA
cfssl gencert -initca ca.json | cfssljson -bare ca
```

#### SSL profile
```shell=
root@raspberrypi:/etc/pki/raspberrypi# /bin/cat<<PROFILE>/etc/pki/raspberrypi/cfssl.json
{
   "signing": {
     "default": {
       "expiry": "17532h"
     },
     "profiles": {
       "intermediate_ca": {
         "usages": [
             "signing",
             "digital signature",
             "key encipherment",
             "cert sign",
             "crl sign",
             "server auth",
             "client auth"
         ],
         "expiry": "17532h",
         "ca_constraint": {
             "is_ca": true,
             "max_path_len": 0, 
             "max_path_len_zero": true
         }
       },
       "peer": {
         "usages": [
             "signing",
             "digital signature",
             "key encipherment", 
             "client auth",
             "server auth"
         ],
         "expiry": "17532h"
       },
       "server": {
         "usages": [
           "signing",
           "digital signing",
           "key encipherment",
           "server auth"
         ],
         "expiry": "17532h"
       },
       "client": {
         "usages": [
           "signing",
           "digital signature",
           "key encipherment", 
           "client auth"
         ],
         "expiry": "17532h"
       }
     }
   }
}
PROFILE
```

#### Intermediate certificate
```shell=
root@raspberrypi:/etc/pki/raspberrypi# /bin/cat<<INTERMEDIATE>/etc/pki/raspberrypi/intermediate-ca.json
{
  "CN": "Barrios Nunez Intermediate CA",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C":  "US",
      "L":  "CT",
      "O":  "Barrios Nunez",
      "OU": "Barrios Nunez Intermediate CA",
      "ST": "USA"
    }
  ],
  "ca": {
    "expiry": "43830h"
  }
}
INTERMEDIATE
cfssl gencert -initca intermediate-ca.json | cfssljson -bare intermediate_ca
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile intermediate_ca intermediate_ca.csr | cfssljson -bare intermediate_ca
```

#### Configuration for the SSL certificate on the Raspberry PI 4 machine

Here we put the name and IP address of the machine that will run our Kismet web application:


```shell=
/bin/cat<<RASPBERRYPI>/etc/pki/raspberrypi/raspberrypi.home.json
{
  "CN": "raspberrypi.home",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "US",
    "L": "CT",
    "O": "Barrios Nunez",
    "OU": "Barrios Nunez Hosts",
    "ST": "USA"
  }
  ],
  "hosts": [
    "raspberrypi.home",
    "localhost",
    "raspberrypi",
    "192.168.1.11"
  ]               
}
RASPBERRYPI
cd /etc/pki/raspberrypi
cfssl gencert -ca intermediate_ca.pem -ca-key intermediate_ca-key.pem -config cfssl.json -profile=peer raspberrypi.home.json| cfssljson -bare raspberry-peer
cfssl gencert -ca intermediate_ca.pem -ca-key intermediate_ca-key.pem -config cfssl.json -profile=server raspberrypi.home.json| cfssljson -bare raspberry-server
cfssl gencert -ca intermediate_ca.pem -ca-key intermediate_ca-key.pem -config cfssl.json -profile=client raspberrypi.home.json| cfssljson -bare raspberry-client
```

Add SSL support to /etc/kismet/kismet_http.conf
```
/bin/cat<<SSL>>/etc/kismet/kismet_http.conf
httpd_ssl=true
httpd_ssl_cert=/etc/pki/raspberrypi/raspberry-server.csr
httpd_ssl_key=/etc/pki/raspberrypi/raspberry-server-key.pem
SSL
```

#### Kismet overrides file

Kismet has a really nice feature, it can use a file that override some of the defaults, without the need to edit multiple files. In this case My installation will override the SSL settings, Wifi interface and log location. So time to update our /etc/rc.local file:

```shell=
#!/bin/bash
# Kismet setup
usb_driver=rt2800usb
wlan=$(ls /sys/bus/usb/drivers/$usb_driver/*/net/)
if [ $? -eq 0 ]; then
    set -ex
    /usr/sbin/ifconfig "$wlan" down
    /usr/sbin/iwconfig "$wlan" mode monitor
    /usr/sbin/ifconfig "$wlan" up
    set +ex
    /bin/cat<<KISMETOVERR>/etc/kismet/kismet_site.conf
server_name=Nunez Barrios Kismet server
source=$wlan
httpd_ssl=true
httpd_ssl_cert=/etc/pki/raspberrypi/raspberry-server.csr
httpd_ssl_key=/etc/pki/raspberrypi/raspberry-server-key.pem
KISMETOVERR
fi
```

Finally it is time to start kismet (in my case as the non root user josevnz):

```shell=
# If you know which interface is the one in monitoring mode, then 
josevnz@raspberrypi:~$ kismet
```
Now let's log for the first time on the web interface (In my case http://raspberripi.home:2501)

![](https://i.imgur.com/rSmLKYA.png)

![](https://i.imgur.com/VNKyT3K.png)

So the wireless devices around me look pretty normal,except one that doesn't have a name:

![](https://i.imgur.com/6JfY7sE.png)


The web interface provides all sorts of useful information, but there is a easy way to filter all the mac addresses on my networks?

Kistmet has a REST API, so it is time to see what we can automate from there.

## REST-API

The [developer documentation](https://www.kismetwireless.net/docs/devel_group.html) contains examples of how to extend Kismet.



# Aircrack-ng

So what is it [aircrack-ng](https://aircrack-ng.org/index.html)?

> Aircrack-ng is a complete suite of tools to assess WiFi network security.
> It focuses on different areas of WiFi security:
> * Monitoring: Packet capture and export of data to text files for further processing by third party tools
> * Attacking: Replay attacks, deauthentication, fake access points and others via packet injection
> * Testing: Checking WiFi cards and driver capabilities (capture and injection)
> * Cracking: WEP and WPA PSK (WPA 1 and 2)





## Installation of Aircrack-ng

```shell=
sudo apt-get install aircrack-ng
sudo apt-get -y install libssl-dev
airodump-ng-oui-update
/usr/sbin/update-ieee-data
Updating /var/lib/ieee-data//oui.txt
	Checking permissions on /var/lib/ieee-data//oui.txt
	Downloading https://standards.ieee.org/develop/regauth/oui/oui.txt to /var/lib/ieee-data//oui.txt
	Checking header
	Temporary location /tmp/ieee-data_y9Ge42 to be moved to /var/lib/ieee-data//oui.txt
	/var/lib/ieee-data//oui.txt updated.
...
```

# Getting to know your hardware
__The Raspberry PI 4 onboard wireless card will not work out of the box as the firmware doesn't support monitor mode__

If you run airmon-ng you will get the following error:

```shell=
josevnz@raspberrypi:~$ sudo airmon-ng start wlan0


PHY	Interface	Driver		Chipset

phy0	wlan0		brcmfmac	Broadcom 43430


ERROR adding monitor mode interface: command failed: Operation not supported (-95)

```

There are works to [support this](https://github.com/seemoo-lab/bcm-rpi3), but you are also risking bricking your hardware. Instead I took the easy way out and ordered an external Wifi dungle from [CanaKit](https://www.canakit.com/raspberry-pi-wifi.html).

The CanaKit wireless card worked out of the box as I will show you next

# Configuring your network interfaces for data capture

First step, let's make sure airmon can take over the network interfaces:
```shell=
josevnz@raspberrypi:~$ sudo airmon-ng check kill
```

```shell=
josevnz@raspberrypi:~$ sudo airmon-ng 

PHY	Interface	Driver		Chipset

phy0	wlan0		brcmfmac	Broadcom 43430
phy1	wlan1   	rt2800usb	Ralink Technology, Corp. RT5370
```

Start airmon-ng, and confirm wlan1 is in monitor mode:

```shell
josevnz@raspberrypi:~$ sudo airmon-ng start wlan1


PHY	Interface	Driver		Chipset

phy0	wlan0		brcmfmac	Broadcom 43430
phy1	wlan1		rt2800usb	Ralink Technology, Corp. RT5370

		(mac80211 monitor mode vif enabled for [phy1]wlan1 on [phy1]wlan1mon)
		(mac80211 station mode vif disabled for [phy1]wlan1)

josevnz@raspberrypi:~$ iwconfig
wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=31 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
docker0   no wireless extensions.

lo        no wireless extensions.

wlan1mon  IEEE 802.11  Mode:Monitor  Frequency:2.457 GHz  Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
          
docker_gwbridge  no wireless extensions.

eth0      no wireless extensions.


```

We can see than 'wlan1mon' is on monitor mode. Good, next step is to see what is around us



# What did we learn?

