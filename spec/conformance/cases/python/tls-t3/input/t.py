import smtplib
import socket
import ssl

import ldap3
from ldap3 import Server, Tls

# TLS uses beyond context creation (DECISIONS P3-TLS)
ctx = ssl._create_unverified_context()  # want: python.cert.validation.disabled ssl._create_unverified_context | python.prot.tls.context ssl._create_unverified_context
sock = ctx.wrap_socket(socket.socket(), server_hostname="h")  # want: python.prot.tls.context ctx.wrap_socket
mail = smtplib.SMTP("mail", 25)  # plain SMTP: nothing
mail.starttls()  # want: python.prot.tls.context mail.starttls
tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)  # want: python.cert.validation.disabled ldap3.Tls | python.prot.tls.v1_2 ldap3.Tls
checked = Tls(validate=ssl.CERT_REQUIRED)  # want: python.prot.tls.context ldap3.Tls
ldaps = Server("dc", use_ssl=True, port=636, tls=tls)  # want: python.prot.tls.context ldap3.Server
plain = Server("dc", use_ssl=False, port=389)  # nothing
conn = ldap3.Connection(plain)  # nothing
conn.start_tls()  # want: python.prot.tls.context conn.start_tls
s = socket.socket().wrap()  # another method: nothing
