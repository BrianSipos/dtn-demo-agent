#!/usr/bin/python3
#
import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import datetime
import jinja2
import logging
import os
import re
import shutil
import subprocess
import sys
import yaml

LOGGER = logging.getLogger()

nodeConfTemplate = jinja2.Template('''\
udpcl:
    log_level: info
    bus_addr: system
    bus_service: org.ietf.dtn.node.udpcl
    node_id: dtn://{{node_name}}/

    dtls_enable_tx: False

    init_listen:
{% if useIpv4 %}
      - address: 0.0.0.0
        multicast_member:
          - addr: 224.0.0.1
{% endif %}
{% if useIpv6 %}
      - address: "::"
        multicast_member:
          - addr: FF02:0:0:0:0:0:0:1
            iface: eth0
{% endif %}

tcpcl:
    log_level: info
    bus_addr: system
    bus_service: org.ietf.dtn.node.tcpcl
    node_id: dtn://{{node_name}}/

    tls_enable: False

    init_listen:
{% if useIpv4 %}
      - address: 0.0.0.0
{% endif %}
{% if useIpv6 %}
      - address: "::"
{% endif %}

bp:
    log_level: info
    bus_addr: system
    bus_service: org.ietf.dtn.node.bp
    node_id: dtn://{{node_name}}/

    verify_ca_file: /etc/xdg/dtn/ca.crt
    sign_cert_file: /etc/xdg/dtn/sign.crt
    sign_key_file: /etc/xdg/dtn/sign.key

    rx_route_table:
      - eid_pattern: "dtn://{{node_name}}/.*"
        action: deliver
      - eid_pattern: ".*"
        action: forward

''')


class Runner:
    ACTIONS = ['prep', 'start', 'stop', 'delete']

    def __init__(self, args):
        self._docker = re.split(r'\s+', os.environ.get('DOCKER', 'docker').strip())

        with open(args.config, 'rb') as conffile:
            self._config = yaml.safe_load(conffile)

    def runcmd(self, parts):
        LOGGER.info('Running command %s', ' '.join(f'"{part}"' for part in parts))
        subprocess.check_call(parts)

    def run_docker(self, args):
        self.runcmd(self._docker + args)

    def action(self, act):
        if act == 'prep':
            img_name_tag = 'dtn-demo'

            LOGGER.info('Building image...')
            self.run_docker(['build', '-t', img_name_tag, '.', '-f', 'container/Dockerfile'])

            LOGGER.info("Ensuring networks...")
            for (net_name, net_opts) in self._config['nets'].items():
                try:
                    self.run_docker(['network', 'inspect', net_name])
                except subprocess.CalledProcessError:
                    LOGGER.info("Creating network %s", net_name)
                    cmd = ['network', 'create', net_name]
                    cmd += ['--subnet', net_opts['subnet']]
                    self.run_docker(cmd)

            with open(os.path.join('testpki', 'ca.key'), 'rb') as infile:
                ca_key = serialization.load_pem_private_key(infile.read(), None)
            with open(os.path.join('testpki', 'ca.crt'), 'rb') as infile:
                ca_cert = x509.load_pem_x509_certificate(infile.read())

            for (node_name, node_opts) in self._config['nodes'].items():
                configPath = os.path.join('container', 'workdir', node_name, 'xdg', 'dtn')
                if not os.path.isdir(configPath):
                    os.makedirs(configPath)

                # Generate node key
                node_key = ec.generate_private_key(ec.SECP256R1)  # Curve for COSE ES256
                with open(os.path.join(configPath, 'sign.key'), 'wb') as outfile:
                    outfile.write(node_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))

                nowtime = datetime.datetime.now(datetime.timezone.utc)
                node_cert = x509.CertificateBuilder().subject_name(
                    x509.Name([
                        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, node_name),
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
                        x509.UniformResourceIdentifier('dtn://{}/'.format(node_name)),
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
                        x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
                    ]),
                    critical=False,
                ).add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
                    critical=False,
                ).add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                    critical=False,
                ).sign(ca_key, hashes.SHA256())
                with open(os.path.join(configPath, 'sign.crt'), 'wb') as outfile:
                    outfile.write(node_cert.public_bytes(serialization.Encoding.PEM))
                shutil.copy(
                    os.path.join('testpki', 'ca.crt'),
                    os.path.join(configPath, 'ca.crt')
                )

                with open(os.path.join(configPath, 'node.yaml'), 'w') as outfile:
                    kwargs = dict(
                        node_name=node_name,
                        useIpv4=True,
                        useIpv6=False,
                    )
                    outfile.write(nodeConfTemplate.render(**kwargs))

                cmd = [
                    'container', 'create',
                    '--mount', f'type=bind,src=container/workdir/{node_name}/xdg/dtn,dst=/etc/xdg/dtn',
                    '--hostname', node_name,
                    '--name', node_name,
                ]
                cmd += ['--network', ','.join(net_name for net_name in node_opts['nets'])]
                cmd += [img_name_tag]
                self.run_docker(cmd)

        elif act == 'start':
            for name in self._config['nodes'].keys():
                self.run_docker(['container', 'start', name])

        elif act == 'stop':
            for name in self._config['nodes'].keys():
                try:
                    self.run_docker(['container', 'stop', name])
                except subprocess.CalledProcessError:
                    pass

        elif act == 'delete':
            for name in self._config['nodes'].keys():
                try:
                    self.run_docker(['container', 'rm', '-f', name])
                except subprocess.CalledProcessError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
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
