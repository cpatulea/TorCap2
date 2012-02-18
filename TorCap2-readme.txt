TorCap2
cat@vv.carleton.ca
http://vv.carleton.ca/~cat/

Description
~~~~~~~~~~~
TorCap2 is a small program based on TorCap (aphex@iamaphex.net) and accomplishing
essentially the same thing: transparently adding SOCKS4a support to just about
any application that accesses the Internet. In my opinion, the main difference
between the two projects is that TorCap is written in Delphi and is around 200K,
while TorCap2 is written purely in C and is about 50K. Also, TorCap2 has a very
simple graphical user interface, while TorCap has none.

License
~~~~~~~
TorCap2 is licensed under the LGPL 3.0 (see license.txt). You may distribute
TorCap2 as-is within an application, whether the application is licensed under
the GPL or not. Any _modifications_ to TorCap2 must be licensed and distributed
under the LGPL, and clearly indicated in the source code.

Installation
~~~~~~~~~~~~
Copy TorCap2.exe and TorCap2.dll in the same folder. When you run your first
application through it, TorCap2.ini will be created, remembering the settings
you used. That's it.

Configuration
~~~~~~~~~~~~~
The SOCKS server should be specified in "address:port" form. The address must
NOT be a host name, but simply an IP address. Valid examples are 127.0.0.1:1080,
192.168.1.104:9050, while INVALID examples are gwhost:1088, server.company.com:123.
The command to be run is the path to an executable, an it can include command-
line arguments to be passed to the application. Make sure to use proper quoting
when the executable path includes spaces
(e.g. "D:\Program Files\Mozilla Firefox\firefox.exe" http://www.google.ca/)

Running
~~~~~~~
Once you set everything properly and clicked Launch, TorCap2 will exit and only
the redirector component will remain loaded inside the application you launched.

Troubleshooting
~~~~~~~~~~~~~~~
In case something isn't going right, TorCap2 should display appropriate error
messages. It hasn't been thoroughly tested (only on Windows XP), so bug reports
are welcome and even encouraged. Thanks!
