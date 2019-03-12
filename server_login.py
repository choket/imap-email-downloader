import argparse
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


def main():
    program_description = "Test whether login credentials are valid on the supplied IMAP server"
    arg_parser = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    arg_parser.add_argument('--help', action='help', help='show this help message and exit')

    arg_parser.add_argument("-u", "--user", "--username", dest="username", required=True,
                                  help="Username. Can either be the full `username@domain.tld` or just the `username`")

    arg_parser.add_argument("-p", "--pass", "--password", dest="password",
                            help="Password. If omitted you will be prompted to enter it when connecting to the server")

    arg_parser.add_argument("-h", "--host", dest="host",
                            help="IP or full domain name of the server")

    arg_parser.add_argument("-P", "--port",
                            help="Port on which the IMAP server is running. Defaults to 143(or 993 if -s is used)")

    arg_parser.add_argument("-s", "--ssl", action="store_true",
                            help="Use SSL when connecting to the server")

    arg_parser.add_argument("-c", "--common", "--common-hosts", dest="common_hosts", action="store_true",
                            help="If connecting to host fails, try common variations of the host such as mail.host and imap.host")

    args = arg_parser.parse_args()
    username = args.username
    password = args.password
    host = args.host
    port = args.port
    ssl = args.ssl
    common_hosts = args.common_hosts

    try:
        server_login(
            username_or_email=username,
            password=password,
            host=host,
            port=port,
            use_ssl=ssl,
            try_common_hosts=common_hosts
        )
    except login_error:
        sys.stdout.write("Invalid!\n")
    except (email_scraper_errors):
        pass
    else:
        sys.stdout.write("Valid!\n")


if __name__ == '__main__':
    main()
