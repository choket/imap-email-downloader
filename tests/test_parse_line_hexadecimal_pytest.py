#!/usr/bin/env python3
import pytest
import re
from imap_account_scraper import parse_line


def test_hexadecimal():
    with open("D:\\password dumps\\extractions\\dot_mk.pog2.txt", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            credentials = parse_line(line)
            if credentials:
                password = credentials["password"]
                assert not re.match(r"^[0-9a-f]{16,}$", password, re.IGNORECASE)


if __name__ == '__main__':
    test_hexadecimal()