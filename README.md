# ns1p - N Shells 1 Port

Accept N reverse shells on one tcp port.
Comes with a terminal UI for session selection and basic auto-stabilization.

~~~
usage: ns1p [-h] [-i IP] [-p PORT] [-r | -l]

Accepts N reverse shell on one tcp port"

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        The IP address to listen on
  -p PORT, --port PORT  The port to listen on
  -r, --force-raw-mode  Disable shell feature checks and force all shells to be in raw mode
  -l, --force-local-prompt-mode
                        Disable shell feature checks and force all shells to be in local prompt mode

Created by B0nk3rZ
~~~

Tested on:
- Arch Linux
- Kali Linux

Not tested on windows but i'm pretty sure it doesn't work there.
