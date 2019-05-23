# IMAP Email Downloader
Download emails from an email account on an IMAP server and save the raw email contents to disk.

Comes with enhanced support for downloading emails from multiple accounts and automatically
extracting login details from text that contains additional data like IP addresses, dates and other
encrypted data.<br>
The latter functionality is useful to extract the login credentials directly 
from database dumps.

# Installation
**Python 3.5 or higher required!**<br>
Clone or download this project to whatever location you like.<br>
The important file are:
* \_\_init\_\_.py
* email_listener.py
* imap_email_downloader.py
* parse_line.py
* server_login.py

You don't need to download the rest for the program to work.

#Usage
Go to the location where you cloned or downloaded the program and open a terminal.<br>
Then you can run the program by typing:
```bash
python3 imap_email_downloader.py <arguments>
```
Or if you are on Linux or Mac:
```bash
./imap_email_downloader.py <arguments>
```
**Note:** If you get an error saying `'python3' is not recognized ...` then replace<br>
`python3` with `python`<br>
_Keep in mind that you need to be running python 3.5 or higher for the program to work_