#!/usr/bin/env python3
import argparse
import imaplib
import os
import shutil
import socket
import sys
import time

from colorama import init as colorama_init

from parse_credentials_from_line import parse_line
from server_login import email_scraper_errors, login_error, connection_error, server_login


class TerminalColors:
	red = '\u001b[31m'
	yellow = '\u001b[33m'
	green = '\u001b[32m'
	end = '\033[0m'


class server_error(email_scraper_errors):
	def __init__(self, message):
		self.message = message

	def __str__(self):
		return self.message


def _count_lines(filename):
	f = open(filename, 'rb')
	lines = 0
	buf_size = 1024 * 1024

	buf = f.read(buf_size)
	while buf:
		lines += buf.count(b'\n')
		buf = f.read(buf_size)

	return lines


def scrape_emails(server, mark_as_read=False, email_parts="all", output_dir=None, verbosity_level=2):
	imap_server_errors = (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error)

	username_or_email = server.username_or_email

	if "@" in username_or_email:
		username = username_or_email.split("@")[0]
	else:
		username = username_or_email

	host = server.host

	if output_dir is None:
		output_dir = host

	if verbosity_level >= 1:
		sys.stdout.write("Downloading emails of {}\n".format(username))

	server.sock.settimeout(5)  # Going to suck my dick now

	try:
		response, mailboxes = server.list()
	except imap_server_errors:
		raise server_error("Error getting mailboxes from server")

	if response != "OK":
		raise server_error("Error getting mailboxes from server")

	if email_parts == "all":
		fetch_parts = "BODY[]"
	elif email_parts == "headers":
		fetch_parts = "BODY[HEADER]"
	elif email_parts == "body":
		fetch_parts = "BODY[TEXT]"
	else:
		sys.stderr.write("Invalid parts to download, defaulting to all\n")
		fetch_parts = "BODY[]"


	for i_mailbox, meta_mailbox in enumerate(mailboxes):
		if '"/"' in meta_mailbox.decode():
			mailbox = meta_mailbox.decode().split('"/" ')[-1]
		else:
			mailbox = meta_mailbox.decode().split("NIL ")[-1]

		response, num_emails_data = server.select(mailbox, readonly=not mark_as_read)

		if response != "OK":
			msg = "\t({}/{}) Error selecting mailbox {} | Reason: {}\n".format(i_mailbox + 1, len(mailboxes), meta_mailbox.decode(), num_emails_data[0].decode())
			sys.stdout.write(msg)
			# raise server_error(msg)
			continue

		num_emails = int(num_emails_data[0].decode())

		mailbox = mailbox.replace("\"", "")


		if output_dir != "":
			mailbox_output_directory = os.path.join(output_dir, username, mailbox)
		else:
			mailbox_output_directory = os.path.join(username, mailbox)


		if not os.path.exists(mailbox_output_directory):
			try:
				os.makedirs(mailbox_output_directory)
			except PermissionError:
				raise PermissionError("Could not create {}, invalid permissions\n".format(mailbox_output_directory))

		response, emails_data = server.search(None, "ALL")

		if response != "OK":
			msg = "Error searching for emails in mailbox: {}\n".format(meta_mailbox.decode())
			sys.stderr.write(msg)
			# raise server_error(msg)
			continue

		emails = emails_data[0].decode().split()

		# TODO clean up all these verbosity checks
		if verbosity_level >= 3:
			# TODO remove the Total emails {} part because we already have the total emails in the progress bar
			sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails\n".format(i_mailbox + 1, len(mailboxes), mailbox, num_emails))
			sys.stdout.flush()

		for i in emails:
			if verbosity_level == 2:
				sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(i_mailbox + 1, len(mailboxes), mailbox, num_emails, i, num_emails))
				sys.stdout.flush()

			if verbosity_level >= 3:
				sys.stdout.write("\t\tDownloading email {}/{}\n".format(i, num_emails))

			try:
				response, email_info = server.fetch(i, "(FLAGS {})".format(fetch_parts))
			except imap_server_errors:
				msg = "Error downloading email {}\n".format(i)
				sys.stderr.write(msg)
				# raise server_error(msg)
				continue

			if response != "OK":
				msg = "Error downloading email {}\n".format(i)
				sys.stderr.write(msg)
				# raise server_error(msg)
				continue

			email_read_status = "READ" if "SEEN" in email_info[0][0].decode().upper() else "UNREAD"
			email_contents = email_info[0][1]
			email_filename = i + "-" + email_read_status + ".eml"
			email_file_path = os.path.join(mailbox_output_directory, email_filename)

			with open(email_file_path, "wb") as fh2:
				fh2.write(email_contents)
		else:
			if not emails and verbosity_level == 2:
				sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(i_mailbox + 1, len(mailboxes), mailbox, 0, 0, 0))
				sys.stdout.flush()

			if verbosity_level == 2:
				sys.stdout.write("\n")  # Print newline to compensate for the last \r which will cause the next line to be overwritten


def batch_scrape(file, host=None, port=None, use_ssl=False, login_only=False, file_delimiter=":", start_offset=0, try_common_hosts=False, mark_as_read=False, email_parts="all", output_dir=None, verbosity_level=2):
	# TODO add a statistic to track how many error connecting to host, incorrect login details and successful login attempts

	invalid_hosts = set()
	valid_hosts = set()

	original_host = host

	num_lines = _count_lines(file)
	num_connection_errors = 0
	num_incorrect_credentials = 0
	num_correct_credentials = 0

	# This makes ANSI color codes work on Windows terminals
	colorama_init()
	terminal_width = shutil.get_terminal_size((80, 20))[0]

	with open(file, "r", encoding="utf-8", errors="ignore") as fh:
		for _ in range(start_offset):
			next(fh)

		valid_credentials_counter = 0
		for i, line in enumerate(fh):

			credentials = parse_line(line, delimiter=file_delimiter)
			if credentials is not None:
				valid_credentials_counter += 1

				# Used to calculate the position to align the statistics to the right side of the terminal
				total_chars_written_to_line = 0

				if original_host is None:
					try:
						host = credentials["email"].split("@")[1]
					except IndexError:
						continue
				else:
					host = original_host

				if try_common_hosts:
					possible_hosts = (host, "imap." + host, "mail." + host)
				else:
					possible_hosts = (host, )

				for test_host in possible_hosts:
					if test_host in invalid_hosts and test_host not in valid_hosts:
						num_connection_errors += 1
						continue

					# Pad the line index to be the same width as the total number of lines
					sys.stdout.write("({}/{}) | ".format(str(i + start_offset).zfill(len(str(num_lines))), num_lines))
					total_chars_written_to_line += len(str(i + start_offset).zfill(len(str(num_lines)))) + len(str(num_lines)) + 6  # 6 chars for the additional symbols
					sys.stdout.flush()

					# Connect to the server
					try:
						server_connection = server_login(
							username_or_email=credentials["email"],
							password=credentials["password"],
							host=test_host,
							port=port,
							use_ssl=use_ssl,
							timeout=0.5  # TODO Refactor this magic number
						)
					except connection_error as error:
						sys.stdout.write(str(error))
						total_chars_written_to_line += len(str(error))

						if error.host not in invalid_hosts and error.host not in valid_hosts:
							# TODO only add host to invalid hosts if connection_error is socket.gainfo error
							invalid_hosts.add(error.host)
							# sys.stderr.write("\n" + error.host + " added to invalid hosts")
							pass


						num_connection_errors += 1

						continue
					except login_error as error:
						sys.stdout.write(str(error))
						total_chars_written_to_line += len(str(error))
						num_incorrect_credentials += 1

						continue
					else:
						valid_hosts.add(test_host)
						num_correct_credentials += 1

						if login_only:
							break

					# Download the emails
					try:
						scrape_emails(
							server=server_connection,
							mark_as_read=mark_as_read,
							email_parts=email_parts,
							output_dir=output_dir,
							verbosity_level=verbosity_level
						)
					except (server_error, PermissionError) as error:
						sys.stderr.write(str(error))

					break

				# The 17 is for the statistic characters which is calculated as 3*XX.XX
				percentage_error = "{:.2%}".format(num_connection_errors/valid_credentials_counter)
				percentage_incorrect = "{:.2%}".format(num_incorrect_credentials/valid_credentials_counter)
				percentage_correct = "{:.2%}".format(num_correct_credentials/valid_credentials_counter)

				padding_size = terminal_width - (total_chars_written_to_line + len(percentage_error) + len(percentage_incorrect) + len(percentage_correct) + 3)
				padding_spaces = " " * padding_size

				sys.stdout.write(padding_spaces + "{red}{}{end} {yellow}{}{end} {green}{}{end}\n".format(
					percentage_error,
					percentage_incorrect,
					percentage_correct,
					red=TerminalColors.red,
					yellow=TerminalColors.yellow,
					green=TerminalColors.green,
					end=TerminalColors.end
				))
				sys.stdout.flush()


def main():
	program_description = "Download emails from an IMAP server and save them to disk in .eml format"
	arg_parser = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter, add_help=False)
	arg_parser.add_argument('--help', action='help', help='show this help message and exit')


	credentials_args = arg_parser.add_mutually_exclusive_group(required=True)


	arg_parser.add_argument("-h", "--host", dest="host",
							help="IP or full domain name of the server")
	arg_parser.add_argument("-c", "--common", "--common-hosts", dest="common_hosts", action="store_true",
							help="If connecting to host fails, try common variations of the host such as mail.host and imap.host")


	credentials_args.add_argument("-u", "--user", "--username", dest="username",
								  help="Username. Can either be the full `username@domain.tld` or just the `username`")
	credentials_args.add_argument("-f", "--file",
								  help="Credentials file.\n" +
									   "A file containing login credentials in the form of `username:password` or `username@domain.tld:password` separated by newlines.\n" +
									   "Downloaded emails are saved under `output_dir/username/mailbox/"
									   "You can specify a custom delimiter instead of `:` by using the -d option")

	arg_parser.add_argument("-p", "--pass", "--password", dest="password",
							help="Password. If omitted you will be prompted to enter it when connecting to the server")
	arg_parser.add_argument("-d", "--file-delimiter", default=":",
							help="A custom delimiter to use when parsing the credentials file to separate the username and password")
	arg_parser.add_argument("-O", "--offset", "--start-offset", dest="start_offset", default=0,
							help="A custom delimiter to use when parsing the credentials file to separate the username and password")

	arg_parser.add_argument("-t", "--threads", default=3,
							help="Number of threads to use when downloading emails from multiple accounts supplied by file credentials.\n" +
								 "Default is 3. Anything above 5 may not work depending on the server"
							)
	arg_parser.add_argument("-P", "--port",
							help="Port on which the IMAP server is running. Defaults to 143(or 993 if -s is used)")
	arg_parser.add_argument("-s", "--ssl", action="store_true",
							help="Use SSL when connecting to the server")
	arg_parser.add_argument("-m", "--mark-as-read", action="store_true",
							help="Use this option to mark the emails as read when downloading them. Default is to NOT mark them as read")
	arg_parser.add_argument("-l", "--login-only", action="store_true",
							help="Only check whether the username and password are valid and don't download any emails")
	arg_parser.add_argument("--parts", "--email-parts", choices=("headers", "body", "all"), default="all",
							help="Specify what parts of the email to download\n" +
								 "headers: Download just the email headers\n" +
								 "body   : Download just the email body\n" +
								 "all    : Download both the headers and body")
	arg_parser.add_argument("-o", "--output-dir",
							help="Output Directory. Defaults to `host`. Pass an empty string to output emails to the current working directory")
	arg_parser.add_argument("-v", "--verbosity-level", choices=("0", "1", "2", "3"), default="2",
							help="Verbosity level. Default level is 2, or 1 when using credentials from a file. Available levels are:\n" +
								 "0) No messages are printed\n" +
								 "1) A message is printed for each user \n" +
								 "2) A message is printed for each mailbox in a user's account \n" +
								 "3) A message is printed for each individual email in a mailbox \n"
							)

	args = arg_parser.parse_args()
	username = args.username
	password = args.password
	host = args.host
	common_hosts = args.common_hosts
	file = args.file
	file_delimiter = args.file_delimiter
	start_offset = int(args.start_offset)
	num_threads = int(args.threads)
	port = args.port
	ssl = args.ssl
	mark_as_read = args.mark_as_read
	login_only = args.login_only
	email_parts = args.parts
	output_dir = args.output_dir
	verbosity_level = int(args.verbosity_level)

	socket.setdefaulttimeout(0.5)  # TODO refactor this magic number


	if file:
		batch_scrape(
			file=file,
			host=host,
			port=port,
			use_ssl=ssl,
			login_only=login_only,
			file_delimiter=file_delimiter,
			start_offset=start_offset,
			try_common_hosts=common_hosts,
			mark_as_read=mark_as_read,
			email_parts=email_parts,
			output_dir=output_dir,
			verbosity_level=verbosity_level
		)
	else:
		try:
			server_connection = server_login(
				username_or_email=username,
				password=password,
				host=host,
				port=port,
				use_ssl=ssl,
				try_common_hosts=common_hosts,
				timeout=0.5  # TODO refactor this magic number
			)

			scrape_emails(
				server=server_connection,
				mark_as_read=mark_as_read,
				email_parts=email_parts,
				output_dir=output_dir,
				verbosity_level=verbosity_level
			)
		except email_scraper_errors as error:
			sys.stderr.write(str(error) + "\n")


if __name__ == "__main__":
	start_time = time.time()
	try:
		main()
	except KeyboardInterrupt:
		sys.stdout.write("\nQuitting...\n")
	sys.stdout.write("Finished in {} seconds\n".format(round(time.time() - start_time, 3)))
