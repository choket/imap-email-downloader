# IMAP Email Downloader
Download emails from an email account on an IMAP server and save the raw email contents to disk.

Comes with enhanced support for downloading emails from multiple accounts, and automatically
extracting login details from text that contains additional data like IP addresses, dates and other
encrypted data.<br>
The latter functionality is useful to extract the login credentials directly 
from database dumps.

## Installation
**Python 3.5 or newer required!**<br>
Clone or download this project to whatever location you like.<br>
The important files are:
* \_\_init\_\_.py
* email_listener.py
* imap_email_downloader.py
* parse_line.py
* server_login.py

You don't need to download the rest for the program to work.

## Usage
Go to the location where you cloned or downloaded the program and open a terminal.<br>
Then you can run the program by executing:
```bash
python3 imap_email_downloader.py <arguments>
```
Or if you are on Linux or Mac:
```bash
./imap_email_downloader.py <arguments>
```
**Note:** If you get an error saying `'python3' is not recognized ...` then replace `python3` with `python`<br>
_Keep in mind that you need to be running python 3.5 or newer for the program to work._


### Available Arguments:
<details>
  <summary>Click to view arguments</summary>
  
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description |
| ------------- |-------------|
| **-u,<br> --user,<br> --username<br>Required** |  Username or complete credentials.<br>The username can either be the full email: `bob@example.com` or just the username: `bob`<br>Or it can contain the email address and password, separated by `:` along with other data commonly found in database dumps<br>If you are entering just the username, then you will also need to enter the host via the **-h** argument|
| -p,<br> --pass,<br> --password | Password. If omitted you will be prompted to enter it when connecting to the server |
| -f,<br> --file | Credentials file.<br>A file containing login credentials in the form of `username:password`<br>or `username@example.com:password` separated by newlines<br>You can specify a custom delimiter instead of `:` by using the **-d** option | 
| -d<br> --delimiter,<br> --file-delimiter | The character which separates the username and password in the credentials file |
| -L,<br> --line,<br> --start-line<br>_Default: 1_ |  Start parsing the credentials file from the N-th line. (Skip the first N-1 lines) |
| -h,<br> --host | IP or full domain name of the IMAP server |
| -P,<br> --port |  Port on which the IMAP server is listening. Default is 143 (or 993 if -s is used) |
| -c,<br> --common-hosts,<br>_Default: False_ | If connecting to host fails, try subdomains such as mail.example.com and imap.example.com |
| -s,<br> --ssl<br>_Default: False_| Use SSL when connecting to the server |
| -t,<br> --timeout<br>_Default: 1_ | Timeout to be used when connecting to the server (in seconds).<br>Anything below 0.5 will result in false-negatives, depending on the server.<br>If using a proxy, specify a higher timeout than normally. |
| -M,<br> --mailbox,<br> --start-mailbox<br>_Default: 1_ |  Start downloading emails from the N-th mailbox. (Skip the first N-1 mailboxes) |
| -E,<br> --email,<br> --start-email<br>_Default: 1_ |  Start downloading emails from the N-th email in the mailbox. (Skip the first N-1 emails) |
| -r,<br> --mark-as-read,<br>_Default: False_ | Use this option to mark the emails as read when downloading them. |
| -l,<br> --login-only<br>_Default: False_ | Just check whether the username and password are valid and don't download any emails |
| --parts,<br> --email-parts<br>_Default: "all"_ | Specify what parts of the email to download. Options are:<br><table> <tr><td>**headers** or **metadata**</td><td>Email headers</td></tr> <tr><td>**body**</td><td>Email body</td></tr> <tr><td>**attachments**</td><td>Just the email attachments</td></tr> <tr><td>**all**</td><td>Entire email</td></tr></table>|
| -o,<br> --output-dir<br>_Default: gets value<br>from **-h** argument_ | Output directory (relative or absolute).<br>Pass an empty string to download emails to the current working directory |
| -v,<br> --verbosity-level<br>_Default: 2_ | Verbosity level. Default level is 2. Available levels are:<br>**0** - No messages are printed<br>**1** - A message is printed for each user<br>**2** - A message is printed for each mailbox in the user's account<br>|
|    --help   | Shows a help message along with usage info |
</details>

## License
[MIT](https://choosealicense.com/licenses/mit/)