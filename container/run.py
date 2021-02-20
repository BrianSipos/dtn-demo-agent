#!/usr/bin/python3
#
import argparse
import datetime
import logging
import os
import re
import shutil
import subprocess
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOGGER = logging.getLogger()

nodeConfTemplate = '''\
udpcl:
    log_level: info
    bus_addr: system
    bus_service: org.ietf.dtn.node.udpcl

    dtls_enable_tx: False
    init_listen:
      - address: 0.0.0.0
        multicast_member:
          - addr: 224.0.0.1

tcpcl:
    log_level: info
    bus_addr: system
    bus_service: org.ietf.dtn.node.tcpcl
    node_id: dtn://{NODENAME}/

    tls_enable: False
    init_listen:
        address: 0.0.0.0

bp:
    log_level: debug
    bus_addr: system
    bus_service: org.ietf.dtn.node.bp
    node_id: dtn://{NODENAME}/

    verify_ca_file: /etc/xdg/dtn/ca.crt
    sign_cert_file: /etc/xdg/dtn/sign.crt
    sign_key_file: /etc/xdg/dtn/sign.key

    rx_route_table:
      - eid_pattern: "dtn://{NODENAME}/.*"
        action: deliver
      - eid_pattern: ".*"
        action: forward

    tx_route_table:
      - eid_pattern: "dtn:~neighbor"
        next_nodeid: "dtn:~neighbor"
        cl_type: udpcl
        address: 224.0.0.1

      - eid_pattern: "dtn://server/.*"
        next_nodeid: dtn://server/
        cl_type: udpcl
        address: 127.0.0.3
'''


class Runner:
    ACTIONS = ['prep', 'start', 'stop', 'delete']

    def __init__(self, args):
        self._docker = re.split(r'\s+', os.environ.get('DOCKER', 'docker').strip())
        self._node_names = [
            'dtn{:03d}'.format(ix)
            for ix in range(args.node_count)
        ]

    def runcmd(self, parts):
        LOGGER.info('Running command %s', parts)
        subprocess.check_call(parts)

    def run_docker(self, args):
        self.runcmd(self._docker + args)

    def action(self, act):
        if act == 'prep':
            img_name_tag = 'dtn-demo'
            net_name = 'dtn-net'

            LOGGER.info('Building image...')
            self.run_docker(['build', '-t', img_name_tag, '.', '-f', 'container/Dockerfile'])

            LOGGER.info("Ensuring network...")
            try:
                self.run_docker(['network', 'inspect', net_name])
            except subprocess.CalledProcessError:
                LOGGER.info("Creating network...")
                self.run_docker(['network', 'create', net_name, '--subnet', '192.168.100.0/24'])

            with open(os.path.join('testpki', 'ca.key'), 'rb') as infile:
                ca_key = serialization.load_pem_private_key(infile.read(), None)
            with open(os.path.join('testpki', 'ca.crt'), 'rb') as infile:
                ca_cert = x509.load_pem_x509_certificate(infile.read())

            for name in self._node_names:
                configPath = os.path.join('container', 'workdir', name, 'xdg', 'dtn')
                if not os.path.isdir(configPath):
                    os.makedirs(configPath)

                # Generate node key
                node_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                with open(os.path.join(configPath, 'sign.key'), 'wb') as outfile:
                    outfile.write(node_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))

                nowtime = datetime.datetime.now(datetime.timezone.utc)
                node_cert = x509.CertificateBuilder().subject_name(
                    x509.Name([
                        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name),
                    ]),
                ).issuer_name(
                    ca_cert.issuer
                ).public_key(
                    node_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    nowtime
                ).not_valid_after(
                    nowtime + datetime.timedelta(days=10)
                ).add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                ).add_extension(
                    x509.SubjectAlternativeName([
                        x509.UniformResourceIdentifier('dtn://{}/'.format(name)),
                    ]),
                    critical=False,
                ).add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=False,
                ).add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.255')
                    ]),
                    critical=False,
                ).sign(ca_key, hashes.SHA256())
                with open(os.path.join(configPath, 'sign.crt'), 'wb') as outfile:
                    outfile.write(node_cert.public_bytes(serialization.Encoding.PEM))
                shutil.copy(
                    os.path.join('testpki', 'ca.crt'),
                    os.path.join(configPath, 'ca.crt')
                )

                with open(os.path.join(configPath, 'node.yaml'), 'w') as outfile:
                    outfile.write(nodeConfTemplate.format(NODENAME=name))

                self.run_docker([
                    'container', 'create',
                    '--mount', 'type=bind,src=container/workdir/{NODENAME}/xdg/dtn,dst=/etc/xdg/dtn'.format(NODENAME=name),
                    '--network', net_name,
                    '--hostname', name,
                    '--name', name,
                    img_name_tag
                ])

        elif act == 'start':
            for name in self._node_names:
                self.run_docker(['container', 'start', name])

        elif act == 'stop':
            for name in self._node_names:
                try:
                    self.run_docker(['container', 'stop', name])
                except subprocess.CalledProcessError:
                    pass

        elif act == 'delete':
            for name in self._node_names:
                try:
                    self.run_docker(['container', 'rm', '-f', name])
                except subprocess.CalledProcessError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node-count', type=int, default=1)
    parser.add_argument('actions', choices=Runner.ACTIONS, nargs='+')
    args = parser.parse_args()
    LOGGER.debug('args %s', args)

    logging.basicConfig(level=logging.DEBUG)

    # do work in parent directory
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

    runner = Runner(args)
    for act in args.actions:
        runner.action(act)


if __name__ == '__main__':
    sys.exit(main())
