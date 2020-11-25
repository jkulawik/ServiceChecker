
# A rudimentary e-mail sender

import socket

EMAIL_TO = 'some@mail.com'
EMAIL_FROM = 'test@service.checker'

# TODO currently doesn't work

def send(subject, content):
    """Send an email using a local mail server."""
    from smtplib import SMTP
    socket.setdefaulttimeout(5.0) # So that this doesn't time out
    server = SMTP(port=587)
    server.connect()
    server.sendmail(EMAIL_FROM, EMAIL_TO, 'Subject: {}\n\n{}'.format(subject, content))
    server.quit()
    socket.setdefaulttimeout(1.0)  # To return to the default value - see top of file
