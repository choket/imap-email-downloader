#!/usr/bin/env python3

# MIT License https://opensource.org/licenses/MIT
#
# Copyright (c) 2019 Stefan Stojanovski https://github.com/choket

import argparse
import re
import sys

from typing import Optional, Dict, Union


def parse_line(line: str,
               delimiter: Optional[str] = ":") -> Union[Dict[str, str], None]:
    """Extract email, password and username from a line containing additional data parts, as common in many database dumps. Each of the data parts must be separated by a delimiter.
    Note that the username is extracted from the email, and doesn't refer to a different username which may be present in the line

    :param line: Line which contains the data to be parsed
    :param delimiter: Delimiter to separate the data parts
    :return: A dictionary with the following keys: "email", "password", "username" containing the extracted values, respectively, or None if no data could be extracted
    """
    # TODO add support for byte strings

    line = line.rstrip()
    data_parts = line.split(delimiter)

    # Remove empty parts
    data_parts = [part for part in data_parts if part]

    email = None
    password = None

    for part in data_parts:
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

            # If there is hexadecimal data in the line, then that will be the password, which is encrypted, so stop parsing the line
            password = None
            break

        if len(part) >= 32 and part.count("$") == 3:
            # Matches data encrypted with modern ciphers

            # Similarly to above, the encrypted data will be the password so set it to None
            password = None
            break

        if password is None:
            password = part

    if email is None or password is None:
        # Line doesn't contain login credentials
        return None
    else:
        username = email.split("@")[0]
        return {"email": email, "password": password, "username": username}


def main():
    program_description = "Extract email, password and username from text containing additional data as well.\n" + \
                          "Returns the email and password joined by \":\" or whatever you set as the delimiter using -d\n" + \
                          "Example: user@example.com:my_password\n"
    ap = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter)

    ap.add_argument("line",
                    help="Text containing the email and password.")
    ap.add_argument("-d", "--delimiter", default=":",
                    help="Delimiter to use break up different parts of data")

    args = ap.parse_args()

    credentials = parse_line(args.line, args.delimiter)

    if credentials:
        print("Email:", credentials["email"])
        print("Password:", credentials["password"])
        print("Username:", credentials["username"])
    else:
        print("Could not extract email and password!", file=sys.stderr)


if __name__ == "__main__":
    main()
