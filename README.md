# IMAP Email Downloader
A program to download emails from an email account on an IMAP server.

Comes with enhanced support for downloading emails from multiple accounts, and automatically
extracting login details from text that contains additional data like IP addresses, dates and encrypted data.<br>
The latter functionality is useful to extract the login credentials directly from dumps of leaked databases.

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
```
python3 imap_email_downloader.py <arguments>
```
Or if you are on Linux or Mac:
```
./imap_email_downloader.py <arguments>
```
**Note:** If you get an error saying `'python3' is not recognized ...` then replace `python3` with `python`<br>
_Keep in mind that you need to be running python 3.5 or newer for the program to work._


### Available Arguments:
<details>
  <summary>View arguments</summary>
  
| &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Description |
| ------------- |-------------|
| **-u,<br> --user,<br> --username<br>_Required_** |  Username or complete credentials.<br>The username can either be the full email: `bob@example.com` or just the username: `bob`<br>Or it can contain the email address and password, separated by `:` along with other data commonly found in database dumps<br>If you are entering just the username, then you will also need to enter the host via the **-h** argument.|
| -p,<br> --pass,<br> --password | Password. If omitted you will be prompted to enter it when connecting to the server. |
| -f,<br> --file | Credentials file.<br>A file containing login credentials in the form of `username:password`<br>or `username@example.com:password` separated by newlines<br>You can specify a custom delimiter instead of `:` by using the **-d** option. | 
| -d,<br> --delimiter,<br> --file-delimiter<br>_Default: ":"_ | The character which separates the username and password in the credentials file. |
| -L,<br> --line,<br> --start-line<br>_Default: 1_ |  Start parsing the credentials file from the _N-th_ line. (Skip the first _N-1_ lines.) |
| -h,<br> --host | IP or full domain name of the IMAP server. |
| -P,<br> --port<br>_Default: 143 or<br>993 if **-s** is used_ |  Port on which the IMAP server is listening. |
| -c,<br> --common-hosts,<br>_Default: False_ | If connecting to host fails, try subdomains such as mail.example.com and imap.example.com |
| -s,<br> --ssl<br>_Default: False_| Use SSL when connecting to the server. |
| -t,<br> --timeout<br>_Default: 1_ | Timeout to be used when connecting to the server (in seconds).<br>Anything below 0.5 will result in false-negatives, depending on the server.<br>If using a proxy, specify a higher timeout than normally. |
| -M,<br> --mailbox,<br> --start-mailbox<br>_Default: 1_ |  Start downloading emails from the _N-th_ mailbox. (Skip the first _N-1_ mailboxes.) |
| -E,<br> --email,<br> --start-email<br>_Default: 1_ |  Start downloading emails from the _N-th_ email in the mailbox. (Skip the first _N-1_ emails.) |
| -r,<br> --mark-as-read,<br>_Default: False_ | Use this option to mark the emails as read when downloading them. |
| -l,<br> --login-only<br>_Default: False_ | Just check whether the username and password are valid and don't download any emails. |
| --parts,<br> --email-parts<br>_Default: "all"_ | Specify what parts of the email to download. Options are:<br><table> <tr><td>**headers** or **metadata**</td><td>Email headers</td></tr> <tr><td>**body**</td><td>Email body</td></tr> <tr><td>**attachments**</td><td>Just the email attachments</td></tr> <tr><td>**all**</td><td>Entire email</td></tr></table>|
| -o,<br> --output-dir<br>_Default: gets value<br>from **-h** argument_ | Output directory (relative or absolute).<br>Pass an empty string to download emails to the current working directory. |
| -v,<br> --verbosity-level<br>_Default: 2_ | Verbosity level. Default level is 2. Available levels are:<br>**0** - No messages are printed<br>**1** - A message is printed for each user<br>**2** - A message is printed for each mailbox in the user's account|
|    --help   | Shows a help message along with usage info. |
</details>

### Examples
Basic example to download all emails from a single account:<br>
```bash
python3 imap_email_downloader.py -u "choket@example.com"
```
<details>
  <summary>Output of the above command</summary>
  
![Single account download](https://media.giphy.com/media/fubXCYknvt7vHo3kHc/giphy.gif)
</details>


You can also supply multiple login credentials via a file.
```bash
python3 imap_email_downloader.py -f "/home/choket/credentials_file.txt"
```
 
 The file must contain login info for each account on a separate line:
```
bob@example.com:123456789
23123412:john@example.com:2019-01-20:secret_password
89.186.46.153:tony@example.com:qwertyiop
...
```
In addition to the email and password, each line can also contain other information, as is common in many files of leaked databases.<br>
This is where the program is most useful -- to download the emails of all accounts present in a database dump.

### _Note about modern email providers_
Nowadays, email providers such as Gmail or Yahoo either have IMAP access disabled by default, or require the use of a one-time password to log in if you have 2FA enabled.<br> 
This one-time password, also known as an _application password_, is different from the password you use to log in and needs to be generated manually.<br>
The process of generating a one-time password depends on the email provider. Specific instructions on how to generate one can usually be found on the email provider's website.

### For developers
The files that make up this project are split into separate components. Each of these components can be used on its own, and can easily be integrated into different projects.<br>
The 3 main components are: 
1. Parsing the user's input: `parse_line.py`
2. Testing whether the login credentials are valid: `server_login.py`
3. Downloading the emails after logging in: `imap_email_downloader.py`

There is also a script, `email_listener.py`, that will search for existing and incoming emails that match a criteria, and then apply a callback function to those emails.<br>
An example of how to use this script is given in `github_email_listener.py`


## License
[MIT](https://choosealicense.com/licenses/mit/)