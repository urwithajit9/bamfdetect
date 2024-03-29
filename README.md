bamfdetect
==========

Identifies and extracts information from bots and other malware.  Information is returned in a readable json format.
bamfdetect works by reading files into RAM, applying any applicable preprocessors, then applying Yara signatures from modules to determine which module it matches.
After a match is located, the module can then extract the configuration from the file.

Currently, only a preprocess for UPX files is supported.  This preprocessor writes the file data to a temporary file, then calls upx -d on the temporary file, and rereads the data from that temporary file.

Currently Supported Malware
---------------------------
 - Alina
 - Andromeda
 - Backoff
 - BlackShades
 - Dendroid
 - Dexter
 - Herpesnet
 - Maazben
 - MadnessPro
 - pBot
 - Pony
 - ProjectHook
 
Module Development
------------------
Until I have time to write a guide for writing modules, please use existing modules as a means of writing your own.
 
Usage
-----
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

./bamfdetect.py v1.4.1 by Brian Wallace (@botnet_hunter)
</pre>


Requirements
------------
 - pefile (python module)
 - yara (python module)
 - rarfile
 - upx (binary)
 
 
Notes
-----
PE files will be checked if they are UPX compressed before being scanned.  If they are, they will be written to a temporary file, then decompressed with the UPX utility.  Yara rules and extraction will then be applied to the resulting data.

This project has been moved from https://github.com/bwall/bamf