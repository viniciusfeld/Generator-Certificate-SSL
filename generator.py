from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

import uuid



def create_ca_file(key, now):

    one_day = timedelta(1, 0, 0)
    public_key = key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'openstack-ansible Test CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'openstack-ansible'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Default CA Deployment'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'openstack-ansible Test CA'),
    ]))
    builder = builder.not_valid_before(datetime.today() - one_day)
    builder = builder.not_valid_after(now + timedelta(days=365))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    print(isinstance(certificate, x509.Certificate))

    with open('ucred_ca.crt', 'wb') as c:
        c.write(certificate.public_bytes(
        encoding=serialization.Encoding.PEM,))




server_ip = '187.1.138.11' # IP da Maquina hospedada
h_name = 'wp10f13.kinghost.net' # Nome da Maquina hospedada

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend,
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, h_name)
])

alt_names = [x509.DNSName(h_name)]
alt_names.append(x509.DNSName(server_ip))
alt_names.append(x509.IPAddress(ipaddress.ip_address(server_ip)))


basic_contrainsts = x509.BasicConstraints(ca=True, path_length=0)
now = datetime.utcnow()

cert = (
    x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(basic_contrainsts, True)
        .add_extension(x509.SubjectAlternativeName(alt_names), False)
        .sign(key, hashes.SHA256(), default_backend())
)

my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
my_key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

create_ca_file(key, now)


with open('ucred_cert.crt', 'wb') as c:
    c.write(my_cert_pem)

with open('ucred_key.pem', 'wb') as c:
    c.write(my_key_pem)