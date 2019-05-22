#!/usr/bin/env python3

# MIT License https://opensource.org/licenses/MIT
#
# Copyright (c) 2019 Stefan Stojanovski https://github.com/choket

import argparse
import getpass
import imaplib
import socket
import sys

from typing import Optional, Union


class email_scraper_errors(Exception): pass


class host_missing(email_scraper_errors):

	def __init__(self, message):
		self.message = message

	def __str__(self):
		return self.message


class connection_error(email_scraper_errors):

	def __init__(self, host, message):
		self.host = host
		self.message = message

	def __str__(self):
		return self.message


class login_error(email_scraper_errors):

	def __init__(self, username, password, message):
		self.username = username
		self.password = password
		self.message = message

	def __str__(self):
		return self.message


def server_login(
		user_or_email_or_combo: str,
		password: Optional[str] = None,
		host: Optional[str] = None,
		port: Optional[int] = None,
		use_ssl: Optional[bool] = False,
		try_common_hosts: Optional[bool] = False,
		no_login: Optional[bool] = False,
		timeout: Optional[Union[float, int]] = None
) -> Union[imaplib.IMAP4, imaplib.IMAP4_SSL]:
	"""Log in to an IMAP server

	:param user_or_email_or_combo: String containing the username, or the email, or the email and password separated by ":"
	:param password: Password to use when logging in
	:param host: IP or domain of the IMAP server
	:param port: Port on which the IMAP server is listening
	:param use_ssl: Use SSL when connecting to the server
	:param try_common_hosts: If connecting to host fails, try connecting to common subdomains of the host on which the server might be running
	:param no_login: Don't log in to the server, just establish a connection
	:param timeout: Maximum number of seconds to try and establish a connection

	:return: imaplib object which is connected to the server, or raise an exception

	:raise host_missing: If the host is not supplied and user_or_email_or_combo also doesn't contain the host
	:raise connection_error: When couldn't connect to the host
	:raise login_error: When couldn't log in with the supplied credentials
	"""
	timeout_errors = (socket.timeout, TimeoutError)
	imap_server_errors = (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error)

	if ":" in user_or_email_or_combo:
		user_or_email, password = user_or_email_or_combo.split(":", 1)
	else:
		user_or_email = user_or_email_or_combo

	if "@" in user_or_email:
		username = user_or_email.split("@", 1)[0]
	else:
		username = user_or_email

	if host is None:
		if "@" in user_or_email:
			host = user_or_email.split("@", 1)[1]
		else:
			raise host_missing("Host must be supplied when using just a username and not a full email address")

	# The schema is not needed and contains invalid filename characters, so remove it
	host = host.replace("http://", "").replace("https://", "")
	host = host.lower()

	if port is None:
		if use_ssl:
			port = 993
		else:
			port = 143

	socket.setdefaulttimeout(timeout)

	if try_common_hosts:
		# Additional hosts to be used if connecting to the original one fails
		# IMAP servers can be commonly found on specific subdomains, not the actual domain
		possible_hosts = (host, "imap." + host, "mail." + host)
	else:
		possible_hosts = (host,)
	for test_host in possible_hosts:
		try:
			if use_ssl:
				server = imaplib.IMAP4_SSL(test_host, port=port)
			else:
				server = imaplib.IMAP4(test_host, port=port)

			break
		# A UnicodeError exception is thrown when the domain name is invalid and IDNA encoding fails
		except (ConnectionError, socket.gaierror, *timeout_errors, *imap_server_errors, UnicodeError) as e:
			msg = "Error connecting to server: {}".format(test_host)

			if try_common_hosts:
				if test_host == possible_hosts[0]:
					sys.stderr.write("Trying common server variations...\n")
				elif test_host == possible_hosts[-1]:
					sys.stderr.write("Couldn't find any variations, exiting\n".format(test_host))
					raise connection_error(test_host, msg)
			else:
				raise connection_error(test_host, msg)


	try:
		server.enable("UTF-8=ACCEPT")
	except (*imap_server_errors, AttributeError):
		# Used to handle utf-8 usernames and passwords
		# Manually setting this in case server.enable("UTF8=ACCEPT") fails which can happen because some old servers
		# either don't support ENABLE command, or don't list utf-8 in their capabilities() but can still handle it
		server._encoding = "utf-8"

	if no_login:
		return server

	if password is None:
		password = getpass.getpass()

	try:
		server.login(username, password)
	except (*timeout_errors, *imap_server_errors):
		msg = "Incorrect details: {}".format(user_or_email)
		raise login_error(user_or_email, password, msg)

	# Add username_or_email to the server object which is later used by scrape_emails()
	setattr(server, "username_or_email", user_or_email)

	return server


def main():
	program_description = "Test whether login credentials are valid on the supplied IMAP server"
	ap = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
	ap.add_argument("--help", action="help", help="show this help message and exit\n\n")

	ap.add_argument("-u", "--user", "--username", dest="username", required=True,
							help="Username or combo.\n" +
								"The username can either be the full email: `bob@example.com` or just the username: `bob`\n" +
								"The combo can contain the email address and password, separated by `:`\n" +
								"along with other data commonly found in database dumps\n\n")
	ap.add_argument("-p", "--pass", "--password", dest="password",
							help="Password. If omitted you will be prompted to enter it when connecting to the server\n\n")

	ap.add_argument("-h", "--host", dest="host",
							help="IP or full domain name of the server\n\n")

	ap.add_argument("-P", "--port",
							help="Port on which the IMAP server is listening. Default is 143 (or 993 if -s is used)\n\n")

	ap.add_argument("-s", "--ssl", action="store_true",
							help="Use SSL when connecting to the server\n\n")

	ap.add_argument("-c", "--common", "--common-hosts", dest="common_hosts", action="store_true",
							help="If connecting to host fails, try variations such as mail.example.com and imap.example.com\n\n")

	ap.add_argument("-t", "--timeout", default=1.0,
							help="Timeout to be used when connecting to the server (in seconds).\n" +
								"Default is 1.\n" +
								"Anything below 0.5 will result in false-negatives, depending on the server.\n" +
								"If using a proxy, specify a higher timeout than normally.\n\n")

	args = ap.parse_args()
	username = args.username
	password = args.password
	host = args.host
	port = args.port
	ssl = args.ssl
	try_common_hosts = args.common_hosts
	timeout = float(args.timeout)


	try:
		server_login(user_or_email_or_combo=username, password=password, host=host, port=port, use_ssl=ssl, try_common_hosts=try_common_hosts, timeout=timeout)
	except login_error:
		sys.stdout.write("Invalid!\n")
	except email_scraper_errors as error:
		sys.stdout.write(str(error) + "\n")
	else:
		sys.stdout.write("Valid!\n")


if __name__ == "__main__":
	main()
