#!/usr/bin/env python3
import re

from imap_email_downloader import parse_line


def test_hexadecimal():
    test_lines = (
        "tony@yahoo.com:1a86be8deadbeef99978",
        "bob@gmail.com:yoloooo:1684eb764feccda",
        "21-03-2015:username:afoijl@gmail.com:4ed0b72556bc7b1b2348bfbaf2957676:secret_password",
    )
    for line in test_lines:
        credentials = parse_line(line)
        if credentials:
            password = credentials["password"]
            assert not re.match(r"^[0-9a-f]{16,}$", password, re.IGNORECASE)
            print(password)


if __name__ == "__main__":
    test_hexadecimal()
