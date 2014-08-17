bamfdetect
==========

Identifies and extracts information from bots and other malware

<pre>cloud@strife:~/git/BAMF$ ./bamfdetect.py -h
usage: ./bamfdetect.py [-h] [-v] [-d] [-r] [-l] [-m MODULE] [path [path ...]]

Identifies and extracts information from bots and other malware

positional arguments:
  path                  Paths to files or directories to scan

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -d, --detect          Only detect files
  -r, --recursive       Scan paths recursively
  -l, --list            List available modules
  -m MODULE, --module MODULE
                        Modules to use, if not definedall modules are used

./bamfdetect.py v1.2.0 by Brian Wallace (@botnet_hunter)
</pre>


Requirements
------------
 - pefile (python module)
 - yara (python module)
 - upx (binary)
 
 
Notes
-----
PE files will be checked if they are UPX compressed before being scanned.  If they are, they will be written to a temporary file, then decompressed with the UPX utility.  Yara rules and extraction will then be applied to the resulting data.

This project has been moved from https://github.com/bwall/bamf