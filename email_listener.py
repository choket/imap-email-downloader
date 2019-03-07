import server_login
import imaplib


def email_listen(server_connection, mailbox, search_query, callback_function=print, *callback_arguments, **callback_kw_arguments):
    try:
        server_connection.select(mailbox)
    except (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error):
        # TODO implement proper exception handling
        raise

    response, emails_data = server_connection.search(None, search_query)

    if response != "OK":
        # TODO implement error handling
        pass

    emails = emails_data[0].decode().split()

    for i in emails:
        callback_function(i, *callback_arguments, **callback_kw_arguments)


def main():
    server = server_login.server_login(
        username_or_email="svetlana-sk",
        password="magdalena",
        host="mail.net.mk"
    )

    email_listen(server, "INBOX", "FROM microsoft", end=" ")


if __name__ == '__main__':
    main()
