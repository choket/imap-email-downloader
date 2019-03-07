import imaplib
import time


def email_listen(server_connection, mailbox, search_query, sleep_timer=10, callback_function=print, *callback_arguments, **callback_kw_arguments):
    """


    :param server_connection: imaplib.IMAP4 or imaplib.IMAP4_SSL object which is already logged in to a server
    :param mailbox: Name of mailbox
    :param search_query: RFC 3501 compliant search query
    :param sleep_timer: Number of seconds to sleep
    :param callback_function:
        function to be called for each of the emails that match the `search_query`
        *NOTE:* the first argument supplied to callback_function() is the email number as returned from the IMAP server
    :param callback_arguments: arguments to supply to callback_function()
    :param callback_kw_arguments: keyword arguments to supply to callback_function()
    :return: None
    """

    try:
        server_connection.select(mailbox)
    except (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error):
        # TODO implement proper exception handling
        raise

    while True:
        try:
            response, emails_data = server_connection.search(None, search_query)
        except:
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
