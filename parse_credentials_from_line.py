#!/usr/bin/env python3
import argparse
import re
import sys

from typing import Optional


def parse_line(
		line: str,
		delimiter: Optional[str] = ":"
):
	# TODO add support for byte strings

	line = line.rstrip()
	data_parts = line.split(delimiter)

	# Remove empty parts
	data_parts = [part for part in data_parts if part]

	# if len(data_parts) == 2:
	#     username = data_parts[0].split("@")[0]
	#     return {"email": data_parts[0], "password": data_parts[1], "username": username}

	email = None
	password = None

	for part in data_parts:

		# Stop parsing the data_parts if we have already found the email and password
		if password is not None and email is not None:
			break

		# Find the email
		if re.match(r"(^[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$)", part.strip(), re.IGNORECASE):
			email = part
			continue
		elif email is None:
			# Don't look for the password until we have found the email
			# The password is almost always located after the email
			continue

		if re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", part):
			# Matches an IPv4 address
			continue

		if re.match(r"^[0-9a-f]{16,}$", part, re.IGNORECASE):
			# Matches hexadecimal data with 16 or more bytes (128 bits). This catches most encrypted data
			continue

		if len(part) >= 32 and part.count("$") == 3:
			# Matches data encrypted with modern ciphers
			continue

		password = part


	if email is None or password is None:
		# Line doesn't contain login credentials
		return None
	else:
		username = email.split("@")[0]
		return {"email": email, "password": password, "username": username}


def main():
	program_description = "Extract email and password from text containing additional data as well.\n" + \
						'Returns the email and password joined by ":" or whatever you set as the delimiter using -d\n' + \
						"Example: user@example.com:my_password\n"
	ap = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter)

	ap.add_argument("line",
					help="Text containing the email and password.")
	ap.add_argument("-d", "--delimiter", default=":",
					help="Delimiter to use break up different parts of data")

	args = ap.parse_args()

	credentials = parse_line(args.line, args.delimiter)

	if credentials:
		print(credentials["email"], credentials["password"], sep=":")
	else:
		sys.stderr.write("Could not extract email and password!\n")


if __name__ == '__main__':
	main()
