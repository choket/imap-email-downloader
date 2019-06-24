#!/usr/bin/env python3

# MIT License https://opensource.org/licenses/MIT
#
# Copyright (c) 2019 Stefan Stojanovski https://github.com/choket

# WEIRD INDEXES EXPLANATION:
# imaplib's fetch() command returns the server response in a weirdly formatted way.
# It returns a tuple containing the server's response status and response data.
# Then additionally, the response data is actually a list containing some metadata and the data itself.
# So, depending on what data was fetch()'ed, we need to dig through the response accordingly to find the actual data

import argparse
import base64
import imaplib
import os
import re
import socket
import sys
import time
from typing import Union, Optional

from parse_line import parse_line
from server_login import server_login, EmailDownloaderErrors, EmailLoginError, EmailConnectionError


class EmailServerError(EmailDownloaderErrors):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


def _count_lines(filename: str):
    """
    Returns number of lines in a file in an optimized way. Useful for big files

    :param filename: Path to file
    :return: Number of lines
    :raise IOError: If the file couldn't be opened
    """
    lines = 0
    buf_size = 1024 * 1024

    with open(filename, "rb") as f:
        read_content = f.read(buf_size)
        while read_content:
            lines += read_content.count(b"\n")
            read_content = f.read(buf_size)

    return lines


def _download_email_attachments(server: Union[imaplib.IMAP4, imaplib.IMAP4_SSL],
                                email_number: str,
                                output_dir: Optional[str] = "attachments") -> None:
    """Download the attachments of an email

    :param server: imaplib object which is logged in and has a mailbox selected
    :param email_number: Number of the email whose attachments to download
    :param output_dir: Directory where to output the attachments
    :return: None
    """
    # output_dir is converted to bytes so that the attachment name, which is bytes, can be appended to it
    output_dir = bytes(output_dir, encoding="utf-8")

    status, body_structure = server.fetch(email_number, "(BODYSTRUCTURE)")

    # See comment at start of file for explanation about the indexes
    body_structure = body_structure[0]

    # body_structure has the attachment filenames in the form of(including quotes): <other_data> ("attachment" ("filename" "<filename>" <other_data>
    # This is a relatively primitive way to search for the attachment filenames
    filename_pattern = re.compile(rb'\("attachment" \("filename" "(.+?)"')

    found_attachments = filename_pattern.findall(body_structure)

    num_attachments = len(found_attachments)

    for i, attachment_name in enumerate(found_attachments, 1):
        charset = "utf-8"

        # Check if attachment name contains non utf-8 characters
        if attachment_name.startswith(b"=?"):

            # The attachment name can consist of multiple sections each encoded with different charsets
            attachment_section_pattern = re.compile(rb"=\?(.+?)\?=(?: |$)")
            attachment_name_sections = attachment_section_pattern.findall(attachment_name)

            attachment_name = b""
            for attachment_name_section in attachment_name_sections:
                charset, encoding_type, attachment_name_part = attachment_name_section.decode().split("?")
                attachment_name_part = bytes(attachment_name_part, encoding="utf-8")

                # attachment_name_part will either be Base64 or Query string encoded

                # Base64 encoding
                if encoding_type == "B":
                    attachment_name += base64.b64decode(attachment_name_part)

                # Query string encoding, where non utf-8 bytes are encoded as their hexadecimal value, prepended by an "=" sign, for example: =D3
                elif encoding_type == "Q":
                    # Function that will convert the hex value from the regex search to a byte
                    hex_to_byte = lambda regex_match: bytes.fromhex(regex_match.group(1).decode())

                    attachment_name += re.sub(rb"=([0-9A-F]{2})", hex_to_byte, attachment_name_part)

        status, attachment_data_container = server.fetch(email_number, "(BODY[{}])".format(i + 1))

        # TODO Check if response == "OK"

        # See comment at start of file for explanation about the indexes
        attachment_data_b64 = attachment_data_container[0][1]
        attachment_raw_data = base64.b64decode(attachment_data_b64)

        # Replace invalid filename characters underscores
        for char in (b">", b"<", b":", b"\"", b"/", b"\\", b"|", b"?", b"*"):
            if char in attachment_name:
                attachment_name = attachment_name.replace(char, b"_")

        try:
            os.makedirs(output_dir, exist_ok=True)
        except PermissionError as e:
            raise PermissionError("Could not create {}, invalid permissions".format(output_dir)) from e

        output_location = os.path.join(output_dir, attachment_name).decode(charset, errors="ignore")
        try:
            attachment_file = open(output_location, "wb")
        except IOError as e:
            sys.stderr.write("Could not write to attachment file. Reason:" + str(e) + "\n")
        else:
            with attachment_file:
                attachment_file.write(attachment_raw_data)

    return num_attachments


def scrape_emails(server: Union[imaplib.IMAP4, imaplib.IMAP4_SSL],
                  mark_as_read: Optional[bool] = False,
                  email_parts: Optional[str] = "all",
                  start_mailbox: Optional[int] = 1,
                  start_email: Optional[int] = 1,
                  output_dir: Optional[str] = None,
                  verbosity_level: Optional[int] = 2) -> None:
    """Download all the emails in an email account via IMAP access

    :param server: imaplib object which is logged in, and has the username or email used to log in set in custom attribute called "username_or_email"
    :param mark_as_read: When set to True, the script will mark all the emails it downloads as Read in the IMAP server
    :param email_parts: What parts of the email to download. Options are:
        "headers" or "metadata": Email headers.
        "body"            : Email body.
        "no-attachments"  : Email headers + body without attachments.
        "attachments"     : Just the email attachments.
        "all"             : Entire email.
    :param start_mailbox: Number of mailbox from which to start downloading emails, effectively skipping all previous ones
    :param start_email: Number of email in the mailbox from which to start downloading, effectively skipping all previous ones
    :param output_dir: Directory where to output the downloaded email.
        A folder will be created for each mailbox and the emails of that mailbox will be placed there
    :param verbosity_level: Available levels are:
        0) No messages are printed
        1) A message is printed for each user
        2) A message is printed for each mailbox in the user's account
    :return: None
    """
    # TODO If mark_as_read is set to True, ask the user for confirmation

    # Classes used to catch imaplib exceptions
    imap_server_errors = (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error)


    # username_or_email is a custom property of imaplib's object that is set when logging in in server_login() function
    if "@" in server.username_or_email:
        username = server.username_or_email.split("@")[0]
    else:
        username = server.username_or_email


    if output_dir is None:
        output_dir = server.host

    if verbosity_level >= 1:
        sys.stdout.write("Downloading emails of {}\n".format(username))

    # Reset the connection timeout back to default value, now that we are already logged in
    # When initially connecting to a server, the timeout is set to a low value, around 1 second
    server.sock.settimeout(15)

    try:
        response, mailboxes = server.list()
    except imap_server_errors:
        raise EmailServerError("Error getting mailboxes from server")

    if response != "OK":
        raise EmailServerError("Error getting mailboxes from server")

    num_mailboxes = len(mailboxes)

    # Decide what parts of the email to download, based on the IMAP rfc
    if email_parts == "all":
        imap_email_parts = "BODY[]"
    elif email_parts == "headers" or email_parts == "metadata":
        # TODO Check if this contains a boundary start as the last line
        imap_email_parts = "BODY[HEADER]"
    elif email_parts == "body":
        # TODO This also downloads attachments. Change it so it only downloads the body
        imap_email_parts = "BODY[TEXT]"
    elif email_parts == "attachments":
        # Downloading email attachments is handled below at the server.fetch() line
        pass
    else:
        sys.stderr.write("Invalid parts to download, defaulting to all!\n")
        imap_email_parts = "BODY[]"

    for i_mailbox, imap_mailbox in enumerate(mailboxes, 1):
        # Skip to the mailbox specified in start_mailbox
        if i_mailbox < start_mailbox:
            continue

        # Extract the name of the mailbox from the server response
        if '"/"' in imap_mailbox.decode(errors="replace"):
            mailbox_name = imap_mailbox.decode(errors="replace").split('"/" ')[-1]
        else:
            mailbox_name = imap_mailbox.decode(errors="replace").split("NIL ")[-1]

        response, num_emails_data = server.select(mailbox_name, readonly=not mark_as_read)

        if response != "OK":
            msg = "\t({}/{}) Error selecting mailbox {} | Reason: {}\n".format(i_mailbox, num_mailboxes, imap_mailbox.decode(errors="replace"), num_emails_data[0].decode(errors="replace"))
            sys.stdout.write(msg)
            # raise server_error(msg)
            continue

        # See comment at start of file for explanation about the indexes
        num_emails = int(num_emails_data[0].decode())

        # Replace invalid filename characters with underscores
        for char in (">", "<", ":", "\"", "/", "\\", "|", "?", "*"):
            if char in mailbox_name:
                mailbox_name = mailbox_name.replace(char, "_")

        if output_dir != "":
            mailbox_output_directory = os.path.join(output_dir, mailbox_name)
        else:
            mailbox_output_directory = mailbox_name

        try:
            os.makedirs(mailbox_output_directory, exist_ok=True)
        except PermissionError as e:
            raise PermissionError("Could not create {}, invalid permissions".format(mailbox_output_directory)) from e

        response, emails_data = server.search(None, "ALL")

        if response != "OK":
            msg = "Error searching for emails in mailbox: {}\n".format(imap_mailbox.decode(errors="replace"))
            sys.stderr.write(msg)
            # raise server_error(msg)
            continue

        # See comment at start of file for explanation about the indexes
        emails = emails_data[0].decode().split()

        for i in emails:
            # Skip to the email specified in start_email
            if int(i) < start_email:
                continue

            if verbosity_level == 2:
                sys.stdout.write(
                    "\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(str(i_mailbox).zfill(len(str(num_mailboxes))), num_mailboxes, mailbox_name, num_emails, i, num_emails))
                sys.stdout.flush()

            if email_parts == "attachments":
                num_attachments = _download_email_attachments(server=server, email_number=i, output_dir=os.path.join(output_dir, mailbox_name, i))
                continue

            try:
                response, fetched_parts = server.fetch(i, "(FLAGS {})".format(imap_email_parts))
            except imap_server_errors as e:
                msg = "\nError downloading email {}\n".format(i)
                sys.stderr.write(msg)
                # raise server_error(msg)
                continue

            if response != "OK":
                msg = "\nError downloading email {}\n".format(i)
                sys.stderr.write(msg)
                # raise server_error(msg)
                continue

            email_contents = b""
            # The last part in fetched_parts is ")", so skip it
            for part in fetched_parts[:-1]:
                email_contents += part[1]

            email_read_status = "READ" if "SEEN" in fetched_parts[0][0].decode().upper() else "UNREAD"
            email_filename = i + "-" + email_read_status + ".eml"
            email_file_path = os.path.join(mailbox_output_directory, email_filename)

            with open(email_file_path, "wb") as email_file:
                email_file.write(email_contents)
        else:
            # Check if there are no emails in mailbox
            if not emails and verbosity_level == 2:
                sys.stdout.write("\t({}/{}) Downloading mailbox: {} | {} Total emails | ({}/{})\r".format(str(i_mailbox).zfill(len(str(num_mailboxes))), num_mailboxes, mailbox_name, 0, 0, 0))
                sys.stdout.flush()

            if verbosity_level == 2:
                # Print newline to compensate for the last \r
                sys.stdout.write("\n")


def batch_scrape(file: str,
                 host: Optional[str] = None,
                 port: Optional[int] = None,
                 use_ssl: Optional[bool] = False,
                 login_only: Optional[bool] = False,
                 file_delimiter: Optional[str] = ":",
                 start_line: Optional[int] = 1,
                 try_common_hosts: Optional[bool] = False,
                 mark_as_read: Optional[bool] = False,
                 email_parts: Optional[str] = "all",
                 output_dir: Optional[str] = None,
                 timeout: Optional[Union[float, int]] = 1.0,
                 verbosity_level: Optional[int] = 2) -> None:
    """Download all the emails of multiple email accounts written in a file via IMAP. Downloaded emails are saved under `output_dir/username/mailbox_name/`

    :param file:
        A file containing login credentials in the form of `username:password`
        or `username@example.com:password` separated by newlines.
        You can specify a custom delimiter instead of `:` by using the file_delimiter parameter
    :param host: IP or domain of the IMAP server
    :param port: Port on which the IMAP server is listening
    :param use_ssl: Use SSL when connecting to the server
    :param login_only: Don't download any emails, just log in and write the valid credentials to the output file or stdout if no output file is given
    :param file_delimiter: Delimiter which separates the email from the password in the input file
    :param start_line: Line number from which to start parsing the input file, effectively skipping all previous ones
    :param try_common_hosts: If connecting to host fails, try connecting to common subdomains of the host on which the server might be running
    :param mark_as_read: When set to True, the script will mark all the emails it downloads as Read in the IMAP server
    :param email_parts: What parts of the email to download. Options are:
        "headers" or "metadata": Email headers.
        "body"            : Email body.
        "no-attachments"  : Email headers + body without attachments.
        "attachments"     : Just the email attachments.
        "all"             : Entire email.
    :param output_dir: Directory where to output the downloaded email.
        A folder will be created for each mailbox and the emails of that mailbox will be placed there
    :param timeout: Maximum number of seconds to try and establish a connection
    :param verbosity_level: Available levels are:
        0) No messages are printed
        1) A message is printed for each user
        2) A message is printed for each mailbox in the user's account
    :return: None
    """
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
            # Skip to the line specified in start_line
            for _ in range(start_line):
                next(credentials_file)

            for i, line in enumerate(credentials_file, 1):

                credentials = parse_line(line, delimiter=file_delimiter)

                # parse_line() function returns None if it couldn't find any credentials in the line specified
                if credentials is None:
                    continue

                if original_host is None:
                    try:
                        host = credentials["email"].split("@")[1].lower()
                    except IndexError:
                        continue
                else:
                    host = original_host.lower()

                # TODO Remove this and use the try_common_hosts parameter of server_login
                if try_common_hosts:
                    # Additional hosts to be used if connecting to the original one fails
                    # IMAP servers can be commonly found on specific subdomains, not the actual domain
                    possible_hosts = (host, "imap." + host, "mail." + host)
                else:
                    possible_hosts = (host,)

                for test_host in possible_hosts:

                    # Skip connecting to the host if it is invalid_hosts, but also specifically check whether it is NOT in valid_hosts.
                    # Even if the IMAP server works as expected, sometimes it can bug out and produce a connection error.
                    # That connection error will cause the host to be added to invalid_hosts, even though it works normally.
                    # So, when successfully connecting to a server we add that server to valid_hosts to make sure it doesn't get skipped
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
                    except EmailConnectionError as error:
                        # Could not connect to host
                        if verbosity_level >= 1:
                            sys.stdout.write(str(error) + "\n")

                        if error.host not in valid_hosts:
                            invalid_hosts.add(error.host)

                        continue
                    except EmailLoginError as error:
                        # Invalid login details

                        if verbosity_level >= 1:
                            sys.stdout.write(str(error) + "\n")

                        break
                    except Exception as e:
                        # Catch any unhandled exceptions and write them to a log file
                        # The script should continue parsing the credentials file until the end, regardless if an exception happened
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
                                output_file = open(output_dir, "a")
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
                    except (EmailServerError, PermissionError) as error:
                        sys.stderr.write(str(error) + "\n")

                    break


def main():
    program_description = "Download all emails from an email account on an IMAP server and save the raw email contents to disk\n"
    program_description += "Downloaded emails are saved under `output_dir/username/mailbox_name/"

    ap = argparse.ArgumentParser(description=program_description, formatter_class=argparse.RawTextHelpFormatter, add_help=False)

    credentials_args = ap.add_mutually_exclusive_group(required=True)

    credentials_args.add_argument("-u", "--user", "--username", dest="username",
                                  help="Username or complete credentials.\n" +
                                       "The username can either be the full email: `bob@example.com` or just the username: `bob`\n" +
                                       "Or it can contain the email address and password, separated by `:`\n" +
                                       "along with other data commonly found in database dumps\n\n")
    ap.add_argument("-p", "--pass", "--password", dest="password",
                    help="Password. If omitted you will be prompted to enter it when connecting to the server\n\n")

    credentials_args.add_argument("-f", "--file",
                                  help="Credentials file.\n" +
                                       "A file containing login credentials in the form of `username:password`\n" +
                                       "or `username@example.com:password` separated by newlines\n" +
                                       "You can specify a custom delimiter instead of `:` by using the -d option\n\n")
    ap.add_argument("-d", "--delimiter", "--file-delimiter", dest="file_delimiter", default=":",
                    help="The character which separates the username and password in the credentials file\n\n")

    ap.add_argument("-h", "--host", dest="host",
                    help="IP or full domain name of the IMAP server\n\n")

    ap.add_argument("-P", "--port",
                    help="Port on which the IMAP server is listening. Default is 143 (or 993 if -s is used)\n\n")

    ap.add_argument("-c", "--common-hosts", dest="common_hosts", action="store_true",
                    help="If connecting to host fails, try subdomains such as mail.example.com and imap.example.com\n\n")

    ap.add_argument("-s", "--ssl", action="store_true",
                    help="Use SSL when connecting to the server\n\n")

    ap.add_argument("-t", "--timeout", default=1.0,
                    help="Timeout to be used when connecting to the server (in seconds).\n" +
                         "Default is 1.\n" +
                         "Anything below 0.5 will result in false-negatives, depending on the server.\n" +
                         "If using a proxy, specify a higher timeout than normally.\n\n")

    ap.add_argument("-L", "--line", "--start-line", dest="start_line", default=1,
                    help="Start parsing the credentials file from the N-th line. (Skip the first N-1 lines)\n\n")
    ap.add_argument("-M", "--mailbox", "--start-mailbox", dest="start_mailbox", default=1,
                    help="Start downloading emails from the N-th mailbox. (Skip the first N-1 mailboxes)\n\n")
    ap.add_argument("-E", "--email", "--start-email", dest="start_email", default=1,
                    help="Start downloading emails from the N-th email in the mailbox. (Skip the first N-1 emails)\n\n")

    ap.add_argument("-r", "--mark-as-read", action="store_true",
                    help="Use this option to mark the emails as read when downloading them.\n" +
                         "Default is to NOT mark them as read\n\n")
    ap.add_argument("-l", "--login-only", action="store_true",
                    help="Just check whether the username and password are valid and don't download any emails\n\n")
    ap.add_argument("--parts", "--email-parts", choices=("headers", "metadata", "body", "no-attachments", "attachments", "all"), default="all",
                    help="Specify what parts of the email to download. Options are:\n" +
                         "headers|metadata: Email headers\n" +
                         "body            : Email body\n" +
                         "attachments     : Just the email attachments\n" +
                         "all             : Entire email\n\n")
    ap.add_argument("-o", "--output-dir",
                    help="Output directory (relative or absolute). Defaults to the same value as `host`.\n" +
                         "Pass an empty string to download emails to the current working directory\n\n")
    ap.add_argument("-v", "--verbosity-level", choices=("0", "1", "2"), default="2",
                    help="Verbosity level. Default level is 2. Available levels are:\n" +
                         "0) No messages are printed\n" +
                         "1) A message is printed for each user\n" +
                         "2) A message is printed for each mailbox in the user's account\n")

    ap.add_argument("--help", action="help", help="Show a help message along with usage info")

    args = ap.parse_args()
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
        batch_scrape(file=credentials_file,
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
                     verbosity_level=verbosity_level)
    else:
        try:
            server_connection = server_login(user_or_email_or_combo=username,
                                             password=password,
                                             host=host,
                                             port=port,
                                             use_ssl=use_ssl,
                                             try_common_hosts=try_common_hosts,
                                             timeout=timeout)

            scrape_emails(server=server_connection,
                          mark_as_read=mark_as_read,
                          email_parts=email_parts,
                          start_mailbox=start_mailbox,
                          start_email=start_email,
                          output_dir=output_dir,
                          verbosity_level=verbosity_level)

        except EmailDownloaderErrors as error:
            sys.stderr.write(str(error) + "\n")


if __name__ == "__main__":
    start_time = time.time()
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\nQuitting...\n")
    sys.stdout.write("Finished in {} seconds\n".format(round(time.time() - start_time, 3)))
