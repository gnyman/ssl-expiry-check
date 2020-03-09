# Author: Lucas Roelser <roesler.lucas@gmail.com>
# Modified from serverlesscode.com/post/ssl-expiration-alerts-with-lambda/

import datetime
import fileinput
import logging
import os
import socket
import ssl
import time
import sys


logger = logging.getLogger('SSLVerify')


def ssl_expiry_datetime(hostname: str) -> datetime.datetime:
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    logger.debug('Connect to {}'.format(hostname))
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


def ssl_valid_time_remaining(hostname: str) -> datetime.timedelta:
    """Get the number of days left in a cert's lifetime."""
    expires = ssl_expiry_datetime(hostname)
    logger.debug(
        'SSL cert for {} expires at {}'.format(
            hostname, expires.isoformat()
        )
    )
    return expires - datetime.datetime.utcnow()


def test_host(hostname: str, buffer_days: int=4):
    """Return test message for hostname cert expiration."""
    try:
        will_expire_in = ssl_valid_time_remaining(hostname)
    except ssl.CertificateError as e:
        return None, f'{hostname} cert error {e}'
    except ssl.SSLError as e:
        return None, f'{hostname} cert error {e}'
    except:
        return None, (f'{hostname} other error %s' % sys.exc_info()[1])
    else:
        if will_expire_in < datetime.timedelta(days=0):
            return f'{hostname} cert has expired', None
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            return f'{hostname} cert will expire in {will_expire_in}', None
        else:
            # everything is fine
            return None,None

if __name__ == '__main__':
    loglevel = os.environ.get('LOGLEVEL', 'INFO')
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

    start = time.time()
    for host in fileinput.input():
        host = host.strip()
        logger.debug('Testing host {}'.format(host))
        try:
            resolv = socket.gethostbyname(host)
            message, error = test_host(host)
            if message:
                print(message)
        except socket.gaierror:
            # don't output anything in case it does not resolve
            continue


    logger.debug('Time: {}'.format(time.time() - start))
