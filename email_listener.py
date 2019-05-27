# MIT License https://opensource.org/licenses/MIT
#
# Copyright (c) 2019 Stefan Stojanovski https://github.com/choket

import imaplib
import time
from typing import Optional, Union, List, Callable, Tuple, Dict


def email_listener(
	server: Union[imaplib.IMAP4, imaplib.IMAP4_SSL],
	mailbox: str,
	search_criteria: Union[str, List[str]],
	sleep_timer: Optional[Union[float, int]] = 10.0,
	callback_function: Optional[Callable] = print,
	callback_arguments: Optional[Union[List, Tuple]] = (),
	callback_kw_arguments: Optional[Dict] = {}
):
	"""
	Setup an email listener which will search for existing and incoming emails that match a criterion,
	and then apply a callback function to those emails. *IMPORTANT: the first argument supplied to the callback function is the email index*

	:param server: imaplib object which is already logged in to a server
	:param mailbox: Name of mailbox folder on which to listen for emails. Eg: "Inbox", "Drafts", "Sent"
	:param search_criteria: RFC 3501 compliant IMAP search criteria. Can also be a list of multiple search criteria
	:param sleep_timer: Number of seconds to sleep in between each scan
	:param callback_function:
		function to be called for each of the emails that match the search criteria.
		IMPORTANT: the first argument supplied to the callback function is the email number
	:param callback_arguments: arguments to supply to the callback function
	:param callback_kw_arguments: keyword arguments to supply to the callback function
	:return: None
	"""

	try:
		# TODO implement parameter which controls the readonly
		server.select(mailbox, readonly=False)
	except (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error):
		# TODO implement proper exception handling
		raise

	while True:
		try:
			response, emails_data = server.search(None, search_criteria)
		except Exception as e:
			# Catch all exceptions because script needs to be resilient
			time.sleep(sleep_timer)
			continue

		if response != "OK":
			time.sleep(sleep_timer)
			continue

		emails = emails_data[0].decode().split()

		for i in emails:
			callback_function(i, *callback_arguments, **callback_kw_arguments)

		time.sleep(sleep_timer)
