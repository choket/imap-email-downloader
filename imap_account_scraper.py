#!/usr/bin/env python3
import argparse
import base64
import imaplib
import os
import re
import socket
import sys
import time

from parse_credentials_from_line import parse_line
from server_login import email_scraper_errors, login_error, connection_error, server_login


class server_error(email_scraper_errors):
	def __init__(self, message):
		self.message = message

	def __str__(self):
		return self.message


def _count_lines(filename):
	"""
	Returns number of lines in a file

	:param filename: Path to file
	:return: Number of lines
	"""
	f = open(filename, 'rb')
	lines = 0
	buf_size = 1024 * 1024

	buf = f.read(buf_size)
	while buf:
		lines += buf.count(b'\n')
		buf = f.read(buf_size)

	f.close()

	return lines


def _download_email_attachments(server_connection, email_number, output_dir="attachments"):
	output_dir = bytes(output_dir, encoding="utf-8")

	response, body_structure = server_connection.fetch(email_number, "(BODYSTRUCTURE)")

	# body_structure is a list containing a single item -- the body structure
	body_structure = body_structure[0]

	# body_structure has the attachment filenames in the form of(including quotes): <other_data> ("attachment" ("filename" "<filename>")) <other_data>
	filename_pattern = re.compile(rb'\("attachment" \("filename" "(.+?)"')

	found_attachments = filename_pattern.findall(body_structure)

	num_attachments = len(found_attachments)

	for i, attachment_name in enumerate(found_attachments, 1):
		charset = "utf-8"

		if attachment_name.startswith(b"=?"):
			attachment_section_pattern = re.compile(rb'=\?(.+?)\?=(?: |$)')
			attachment_name_sections = attachment_section_pattern.findall(attachment_name)

			attachment_name = b""
			for attachment_name_section in attachment_name_sections:
				charset, encoding_type, attachment_name_part = attachment_name_section.decode().split("?")
				attachment_name_part = bytes(attachment_name_part, encoding="utf-8")

				# The attachment name section is base64 encoded
				if encoding_type == "B":
					attachment_name += base64.b64decode(attachment_name_part)
				# Special bytes are hexadecimally encoded as =XX
				elif encoding_type == "Q":
					hex_to_byte = lambda regex_match: bytes.fromhex(regex_match.group(1).decode())
					attachment_name += re.sub(rb"=([0-9A-F]{2})", hex_to_byte, attachment_name_part)

		response, attachment_data_container = server_connection.fetch(email_number, "(BODY[{}])".format(i + 1))
		attachment_data_b64 = attachment_data_container[0][1]
		attachment_raw_data = base64.b64decode(attachment_data_b64)

		for char in (b">", b"<", b":", b"\"", b"/", b"\\", b"|", b"?", b"*"):
			if char in attachment_name:
				attachment_name = attachment_name.replace(char, b"_")

		try:
			os.makedirs(output_dir, exist_ok=True)
		except FileExistsError:
			pass

		output_location = os.path.join(output_dir, attachment_name).decode(charset)
		try:
			attachment_file = open(output_location, "wb")
		except IOError as e:
			sys.stderr.write("Could not open input file. Reason:" + str(e) + "\n")
		else:
			with attachment_file:
				attachment_file.write(attachment_raw_data)

		pass

	return num_attachments


def scrape_emails(
		server, mark_as_read=False, email_parts="all", start_mailbox=1,
		start_email=1, output_dir=None, verbosity_level=2
):
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

	num_mailboxes = len(mailboxes)

	# TODO add option "no-attachments" to only download the body+headers and no attachments
	if email_parts == "all":
		fetch_parts = "BODY[]"
	elif email_parts == "headers" or email_parts == "metadata":
		fetch_parts = "BODY[HEADER]"
	elif email_parts == "body":
		fetch_parts = "BODY[TEXT]"
	elif email_parts == "attachments":
		# Downloading email attachments is handled below at the fetch() line
		pass
	else:
		sys.stderr.write("Invalid parts to download, defaulting to all!\n")
		fetch_parts = "BODY[]"

	for i_mailbox, imap_mailbox in enumerate(mailboxes, 1):
		if i_mailbox < start_mailbox:
			continue

		if '"/"' in imap_mailbox.decode(errors="replace"):
			mailbox_folder = imap_mailbox.decode(errors="replace").split('"/" ')[-1]
		else:
			mailbox_folder = imap_mailbox.decode(errors="replace").split("NIL ")[-1]

		response, num_emails_data = server.select(mailbox_folder, readonly=not mark_as_read)

		if response != "OK":
			msg = "\t({}/{}) Error selecting mailbox {} | Reason: {}\n".format(i_mailbox, num_mailboxes, imap_mailbox.decode(errors="replace"), num_emails_data[0].decode(errors="replace"))
			sys.stdout.write(msg)
			# raise server_error(msg)
			continue

		num_emails = int(num_emails_data[0].decode(errors="replace"))

		mailbox_folder = mailbox_folder.replace("\"", "")


		if output_dir != "":
			mailbox_output_directory = os.path.join(output_dir, mailbox_folder)
		else:
			mailbox_output_directory = mailbox_folder


		try:
			os.makedirs(mailbox_output_directory, exist_ok=True)
		except PermissionError:
			raise PermissionError("Could not create {}, invalid permissions\n".format(mailbox_output_directory))

		response, emails_data = server.search(None, "ALL")

		if response != "OK":
			msg = "Error searching for emails in mailbox: {}\n".format(imap_mailbox.decode(errors="replace"))
			sys.stderr.write(msg)
			# raise server_error(msg)
			continue

		emails = emails_data[0].decode(errors="replace").split()


		for i in emails:

			if int(i) < start_email:
				continue

			if verbosity_level == 2:
				sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(str(i_mailbox).zfill(len(str(num_mailboxes))), num_mailboxes, mailbox_folder, num_emails, i, num_emails))
				sys.stdout.flush()

			if email_parts == "attachments":
				num_attachments = _download_email_attachments(server_connection=server, email_number=i, output_dir=os.path.join(output_dir, mailbox_folder, i))
				continue


			try:
				response, email_info = server.fetch(i, "(FLAGS {})".format(fetch_parts))
			except imap_server_errors:
				msg = "\nError downloading email {}\n".format(i)
				sys.stderr.write(msg)
				# raise server_error(msg)
				continue

			if response != "OK":
				msg = "\nError downloading email {}\n".format(i)
				sys.stderr.write(msg)
				# raise server_error(msg)
				continue

			email_read_status = "READ" if "SEEN" in email_info[0][0].decode(errors="replace").upper() else "UNREAD"
			email_contents = email_info[0][1]
			email_filename = i + "-" + email_read_status + ".eml"
			email_file_path = os.path.join(mailbox_output_directory, email_filename)

			with open(email_file_path, "wb") as fh2:
				fh2.write(email_contents)
		else:
			# Check if there are no emails in mailbox
			if not emails and verbosity_level == 2:
				sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(str(i_mailbox).zfill(len(str(num_mailboxes))), num_mailboxes, mailbox_folder, 0, 0, 0))
				sys.stdout.flush()

			if verbosity_level == 2:
				sys.stdout.write("\n")  # Print newline to compensate for the last \r which will cause the next line to be overwritten


def batch_scrape(
		file, host=None, port=None, use_ssl=False, login_only=False, file_delimiter=":", start_line=1,
		try_common_hosts=False, mark_as_read=False, email_parts="all", output_dir=None, timeout=1.0, verbosity_level=2
):
	invalid_hosts = set()
	valid_hosts = set()

	try:
		num_lines = _count_lines(file)
	except IOError:
		num_lines = 0

	original_host = host
	# offset by -1 to skip TO N-th line instead of skipping N lines
	start_line -= 1

	try:
		credentials_file = open(file, "r", encoding="utf-8", errors="ignore")
	except IOError as e:
		sys.stderr.write("Could not open input file. Reason:" + str(e) + "\n")
	else:
		with credentials_file:
			for _ in range(start_line):
				next(credentials_file)

			for i, line in enumerate(credentials_file, 1):

				credentials = parse_line(line, include_username=True, delimiter=file_delimiter)
				if credentials is None:
					continue

				if original_host is None:
					try:
						host = credentials["email"].split("@")[1].lower()
					except IndexError:
						continue
				else:
					host = original_host.lower()

				if try_common_hosts:
					possible_hosts = (host, "imap." + host, "mail." + host)
				else:
					possible_hosts = (host, )

				for test_host in possible_hosts:
					if test_host in invalid_hosts and test_host not in valid_hosts:
						continue

					if verbosity_level >= 1:
						# Pad the line index to be the same width as the total number of lines
						sys.stdout.write("({}/{}) | ".format(str(i + start_line).zfill(len(str(num_lines))), num_lines))
						sys.stdout.flush()

					# Connect to the server
					try:
						server_connection = server_login(
							user_or_email_or_combo=credentials["email"],
							password=credentials["password"],
							host=test_host,
							port=port,
							use_ssl=use_ssl,
							timeout=timeout
						)
					except connection_error as error:
						if verbosity_level >= 1:
							sys.stdout.write(str(error) + "\n")

						if error.host not in valid_hosts:
							invalid_hosts.add(error.host)
							# sys.stderr.write("|" + error.host + " added to invalid hosts")

						continue
					except login_error as error:
						# if not login_only:
						# 	sys.stdout.write(str(error) + "\n")

						if verbosity_level >= 1:
							sys.stdout.write(str(error) + "\n")

						break
					except KeyboardInterrupt:
						raise
					# Script should move on to the next line in the file and not break if an exception happens
					except Exception as e:
						msg = "An unhandled exception occurred at line {}:\n{}\n".format(i + start_line, str(e))
						sys.stderr.write(msg)

						with open(os.path.join(output_dir, "error_log.txt"), "a") as log:
							log.write(msg + "\n")

						break
					else:
						valid_hosts.add(test_host)

						if login_only:
							if verbosity_level >= 1:
								sys.stdout.write("Valid credentials: " + credentials["email"] + file_delimiter + credentials["password"] + "\n")

							try:
								output_file = open(output_dir, 'a')
							except IOError as e:
								sys.stderr.write("Could not open output file. Reason:" + str(e) + "\n")
							else:
								with output_file:
									output_file.write(credentials["email"] + file_delimiter + credentials["password"] + "\n")

							break


					# Download the emails
					try:
						scrape_emails(
							server=server_connection,
							mark_as_read=mark_as_read,
							email_parts=email_parts,
							output_dir=os.path.join(output_dir, test_host, credentials["username"]),
							verbosity_level=verbosity_level
						)
					except (server_error, PermissionError) as error:
						sys.stderr.write(str(error) + "\n")

					break


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
										"A file containing login credentials in the form of `username:password` or `username@domain.tld:password` separated by newlines\n" +
										"Downloaded emails are saved under `output_dir/username/mailbox/"
										"You can specify a custom delimiter instead of `:` by using the -d option")

	arg_parser.add_argument("-p", "--pass", "--password", dest="password",
							help="Password. If omitted you will be prompted to enter it when connecting to the server")
	arg_parser.add_argument("-d", "--file-delimiter", default=":",
							help="A custom delimiter to use when parsing the credentials file to separate the username and password")
	arg_parser.add_argument("-L", "--line", "--start-line", dest="start_line", default=1,
							help="Start parsing the credentials file from the N-th line. (Skip the first N-1 lines)")
	arg_parser.add_argument("-M", "--mailbox", "--start-mailbox", dest="start_mailbox", default=1,
							help="Start download from the N-th mailbox. (Skip the first N-1 mailboxes)")
	arg_parser.add_argument("-E", "--email", "--start-email", dest="start_email", default=1,
							help="Start download from the N-th email in the mailbox. (Skip the first N-1 emails)")

	arg_parser.add_argument("-t", "--timeout", default=1,
							help="Timeout to be used when connecting to the server (in seconds).\n" +
								"Default is 1. Anything below 0.5 will result in false-negatives, depending on the server you're connecting to. \n" +
								"If using a proxy, specify a higher timeout than normally.")
	arg_parser.add_argument("-P", "--port",
							help="Port on which the IMAP server is running. Defaults to 143(or 993 if -s is used)")
	arg_parser.add_argument("-s", "--ssl", action="store_true",
							help="Use SSL when connecting to the server")
	arg_parser.add_argument("-m", "--mark-as-read", action="store_true",
							help="Use this option to mark the emails as read when downloading them. Default is to NOT mark them as read")
	arg_parser.add_argument("-l", "--login-only", action="store_true",
							help="Only check whether the username and password are valid and don't download any emails")
	arg_parser.add_argument("--parts", "--email-parts", choices=("headers", "metadata", "body", "no-attachments", "attachments", "all"), default="all",
							help="Specify what parts of the email to download\n" +
								"headers|metadata: Email headers\n" +
								"body            : Email body\n" +
								"no-attachments  : Email headers + body (no attachments)\n"
								"all             : Both headers and body")
	arg_parser.add_argument("-o", "--output-dir",
							help="Output Directory. Defaults to `host`. Pass an empty string to output emails to the current working directory")
	arg_parser.add_argument("-v", "--verbosity-level", choices=("0", "1", "2"), default="2",
							help="Verbosity level. Default level is 2. Available levels are:\n" +
								"0) No messages are printed\n" +
								"1) A message is printed for each user \n" +
								"2) A message is printed for each mailbox in a user's account \n")

	args = arg_parser.parse_args()
	username = args.username
	password = args.password
	host = args.host
	try_common_hosts = args.common_hosts
	credentials_file = args.file
	file_delimiter = args.file_delimiter
	start_line = int(args.start_line)
	start_mailbox = int(args.start_mailbox)
	start_email = int(args.start_email)
	timeout = float(args.timeout)
	port = args.port
	use_ssl = args.ssl
	mark_as_read = args.mark_as_read
	login_only = args.login_only
	email_parts = args.parts
	output_dir = args.output_dir
	verbosity_level = int(args.verbosity_level)

	socket.setdefaulttimeout(timeout)

	if credentials_file:
		batch_scrape(
			file=credentials_file,
			host=host,
			port=port,
			use_ssl=use_ssl,
			login_only=login_only,
			file_delimiter=file_delimiter,
			start_line=start_line,
			try_common_hosts=try_common_hosts,
			mark_as_read=mark_as_read,
			email_parts=email_parts,
			output_dir=output_dir,
			timeout=timeout,
			verbosity_level=verbosity_level
		)
	else:
		try:
			server_connection = server_login(
				user_or_email_or_combo=username,
				password=password,
				host=host,
				port=port,
				use_ssl=use_ssl,
				try_common_hosts=try_common_hosts,
				timeout=timeout
			)

			scrape_emails(
				server=server_connection,
				mark_as_read=mark_as_read,
				email_parts=email_parts,
				start_mailbox=start_mailbox,
				start_email=start_email,
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
