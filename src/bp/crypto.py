from typing import List, TextIO
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# id-on-bundleEID
OID_ON_EID = x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.8.11')


def load_pem_key(infile: TextIO):
    ''' Read a private key from file.
    '''
    return serialization.load_pem_private_key(infile.read(), None, default_backend())


def load_pem_chain(infile: TextIO) -> List[x509.Certificate]:
    ''' Read a certificate chain from file.
    '''
    certs = []
    chunk = b''
    while True:
        line = infile.readline()
        chunk += line
        if b'END CERTIFICATE' in line.upper():
            cert = x509.load_pem_x509_certificate(chunk, default_backend())
            certs.append(cert)
            chunk = b''
        if not line:
            return certs


def encode_der_cert(cert: x509.Certificate) -> bytes:
    ''' Encode a certificate as DER bytes.
    '''
    return cert.public_bytes(serialization.Encoding.DER)
