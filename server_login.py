import getpass
import imaplib
import socket
import sys


class email_scraper_errors(Exception): pass

class host_missing(email_scraper_errors):

    def __init__(self, host, message):
        self.host = host
        self.message = message


class connection_error(email_scraper_errors):

    def __init__(self, host, message):
        self.host = host
        self.message = message


class login_error(email_scraper_errors):

    def __init__(self, username, password, message):
        self.username = username
        self.password = password
        self.message = message


class server_error(email_scraper_errors):

    def __init__(self, message):
        self.message = message


def server_login(username_or_email, password=None, host=None, port=None, use_ssl=False, try_common_hosts=False, no_login=False, timeout=None):
    # TODO implement username:password@domain.tld login capability

    timeout_errors = (socket.timeout, TimeoutError)
    imap_server_errors = (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error)

    if host is None:
        if "@" in username_or_email:
            host = username_or_email.split("@")[1]
        else:
            msg = "Host must be supplied when using just a username and not a full email address"
            sys.stderr.write(msg)
            raise host_missing(host, msg)

    host = host.replace("http://", "").replace("https://", "")  # TODO check if removing the schema is even needed

    if port is None:
        if use_ssl:
            port = 993
        else:
            port = 143

    possible_hosts = (host, "imap." + host, "mail." + host)
    for test_host in possible_hosts:
        try:
            if use_ssl:
                server = imaplib.IMAP4_SSL(test_host, port=port)
            else:
                server = imaplib.IMAP4(test_host, port=port)

            break
        except (ConnectionRefusedError, ConnectionResetError, socket.gaierror, *timeout_errors, *imap_server_errors) as error:
            sys.stderr.write(str(error) + "\n")
            msg = "Error connecting to server: {}\n".format(test_host)
            sys.stdout.write(msg)

            if not try_common_hosts:
                raise connection_error(test_host, msg)

            if test_host == possible_hosts[0]:
                sys.stderr.write("Trying common server variations\n")
            elif test_host == possible_hosts[-1]:
                sys.stderr.write("Couldn't find any variations, exiting\n".format(test_host))
                raise connection_error(test_host, msg)

    try:
        server.enable("UTF-8=ACCEPT")
    except (*imap_server_errors, AttributeError):
        # Used to handle utf-8 usernames and passwords
        # Manually setting this in case server.enable("UTF8=ACCEPT") fails which can happen because some old servers
        # either don't support ENABLE command, or don't list utf-8 in their capabilities() but can still handle it
        server._encoding = "utf-8"

    server.sock.settimeout(timeout)

    if no_login:
        return server

    if password is None:
        password = getpass.getpass()

    try:
        server.login(username_or_email, password)
    except (*timeout_errors, *imap_server_errors):
        msg = "Incorrect details | {}:{}\n".format(username_or_email, password)
        sys.stdout.write(msg)
        raise login_error(username_or_email, password, msg)

    setattr(server, "username_or_email", username_or_email)

    return server
