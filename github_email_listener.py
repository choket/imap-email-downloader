#!/usr/bin/env python3

# MIT License https://opensource.org/licenses/MIT
#
# Copyright (c) 2019 Stefan Stojanovski https://github.com/choket

import datetime
import os

from email_listener import email_listener
from server_login import server_login


def save_and_delete(email_index, server, mailbox):
    output_directory = "C:\\Users\\Stefan\\Github emails"

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    server.select(mailbox)

    response, email_info = server.fetch(email_index, "(FLAGS BODY[])")
    email_contents = email_info[0][1]

    email_read_status = "READ" if "SEEN" in email_info[0][0].decode().upper() else "UNREAD"
    email_filename = email_index + "-" + email_read_status + str(datetime.datetime.now()).replace(":", "-") + ".eml"
    email_file_path = os.path.join(output_directory, email_filename)

    with open(email_file_path, "wb") as email_file:
        email_file.write(email_contents)

    print("Email number:", email_index, " written to ", email_file_path)

    server.store(email_index, "+FLAGS", "\\Deleted")
    server.expunge()

    print("Deleted email number:", email_index)


def main():
    server = server_login(
        user_or_email_or_combo="bob@example.com",  # Change this to your email
        password="12345678"  # Change this to your password
    )

    email_listener(
        server=server,
        mailbox="INBOX",
        search_criteria="FROM github",
        callback_function=save_and_delete,
        callback_kw_arguments={
            "server": server,
            "mailbox": "INBOX"
        }
    )


if __name__ == "__main__":
    main()
