import imaplib
import time
from typing import Optional, Union, List, Callable, Tuple, Dict


def email_listen(
		server_connection: Union[imaplib.IMAP4, imaplib.IMAP4_SSL],
		mailbox: str,
		search_query: Union[str, List[str]],
		sleep_timer: Optional[Union[float, int]] = 10.0,
		callback_function: Optional[Callable] = print,
		callback_arguments: Optional[Union[List, Tuple]] = (),
		callback_kw_arguments: Optional[Dict] = {}
):
	"""
	:param server_connection: imaplib object which is already logged in to a server
	:param mailbox: Name of mailbox
	:param search_query: RFC 3501 compliant IMAP search query
	:param sleep_timer: Number of seconds to sleep
	:param callback_function:
		function to be called for each of the emails that match the `search_query`
		*NOTE:* the first argument supplied to callback_function() is the email number as returned from the IMAP server
	:param callback_arguments: arguments to supply to callback_function()
	:param callback_kw_arguments: keyword arguments to supply to callback_function()
	:return: None
	"""

	try:
		# TODO implement parameter which controls the readonly
		server_connection.select(mailbox, readonly=False)
	except (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error):
		# TODO implement proper exception handling
		raise

	while True:
		try:
			response, emails_data = server_connection.search(None, search_query)
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
