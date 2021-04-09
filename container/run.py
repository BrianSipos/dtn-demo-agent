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
SELFDIR = os.path.dirname(os.path.abspath(__file__))

class Runner:
    ACTIONS = ['prep', 'start', 'stop', 'delete']

    def __init__(self, args):
        self.args = args
        self._docker = re.split(r'\s+', os.environ.get('DOCKER', 'docker').strip())

        with open(args.config, 'rb') as conffile:
            self._config = yaml.safe_load(conffile)

    def runcmd(self, parts, **kwargs):
        LOGGER.info('Running command %s', ' '.join(f'"{part}"' for part in parts))
        subprocess.check_call(parts, **kwargs)

    def run_docker(self, args):
        env = {
            'DOCKER_BUILDKIT': '1',
        }
        self.runcmd(self._docker + args, env=env)

    def action(self, act):
        if act == 'prep':
            img_name_tag = 'dtn-demo'

            LOGGER.info('Building image...')
            cmd = ['build', '-t', img_name_tag, '.', '-f', 'container/Dockerfile']
            if self.args.image_no_cache:
                cmd += ['--no-cache']
            self.run_docker(cmd)

            LOGGER.info("Ensuring networks...")
            for (net_name, net_opts) in self._config['nets'].items():
                try:
                    self.run_docker(['network', 'inspect', net_name])
                except subprocess.CalledProcessError:
                    LOGGER.info("Creating network %s", net_name)
                    cmd = ['network', 'create', net_name]
                    if 'subnet4' in net_opts:
                        cmd += ['--subnet', net_opts['subnet4']]
                    if 'subnet6' in net_opts:
                        cmd += ['--ipv6', '--subnet', net_opts['subnet6']]
                    self.run_docker(cmd)

            with open(os.path.join('testpki', 'ca.key'), 'rb') as infile:
                ca_key = serialization.load_pem_private_key(infile.read(), None)
            with open(os.path.join('testpki', 'ca.crt'), 'rb') as infile:
                ca_cert = x509.load_pem_x509_certificate(infile.read())

            for (node_name, node_opts) in self._config['nodes'].items():
                fqdn = node_name + '.local'

                configPath = os.path.join('container', 'workdir', node_name, 'xdg', 'dtn')
                if not os.path.isdir(configPath):
                    os.makedirs(configPath)

                # Generate node keys
                for key_name in ('transport', 'sign'):
                    node_key = ec.generate_private_key(ec.SECP256R1)  # Curve for COSE ES256
                    with open(os.path.join(configPath, f'{key_name}.key'), 'wb') as outfile:
                        outfile.write(node_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        ))

                    nowtime = datetime.datetime.now(datetime.timezone.utc)
                    sans = [
                        x509.UniformResourceIdentifier('dtn://{}/'.format(node_name)),
                    ]
                    ekus = [
                        x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
                    ]
                    if key_name == 'transport':
                        sans += [
                            x509.DNSName(fqdn),
                        ]
                        ekus += [
                            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        ]

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
                        x509.SubjectAlternativeName(sans),
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
                        x509.ExtendedKeyUsage(ekus),
                        critical=False,
                    ).add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
                        critical=False,
                    ).add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                        critical=False,
                    ).sign(ca_key, hashes.SHA256())
                    with open(os.path.join(configPath, f'{key_name}.crt'), 'wb') as outfile:
                        outfile.write(node_cert.public_bytes(serialization.Encoding.PEM))

                shutil.copy(
                    os.path.join('testpki', 'ca.crt'),
                    os.path.join(configPath, 'ca.crt')
                )

                extconfig = node_opts.get('config', {})
                use_ipv4 = node_opts.get('use_ipv4', True)
                use_ipv6 = node_opts.get('use_ipv6', True)
                nodeid = 'dtn://{}/'.format(node_name)

                udpcl_listen = []
                if extconfig.get('udpcl_listen', True):
                    if use_ipv4:
                        udpcl_listen.append({
                            'address': '0.0.0.0',
                            'multicast_member': [
                                {
                                    'addr': '224.0.0.1',
                                },
                            ],
                        })
                    if use_ipv6:
                        udpcl_listen.append({
                            'address': '::',
                            'multicast_member': [
                                {
                                    'addr': 'FF02:0:0:0:0:0:0:1',
                                    'iface': 'eth0',
                                },
                            ],
                        })

                tcpcl_listen = []
                if extconfig.get('tcpcl_listen', True):
                    if use_ipv4:
                        tcpcl_listen.append({
                            'address': '0.0.0.0',
                        })
                    if use_ipv6:
                        tcpcl_listen.append({
                            'address': '::',
                        })

                bp_rx_routes = extconfig.get('bp_rx_routes', [])
                bp_rx_routes += [
                    {
                        'eid_pattern': r'dtn://{{node_name}}/.*',
                        'action': 'deliver',
                    },
                    {
                        'eid_pattern': '".*"',
                        'action': 'forward',
                    },
                ]
                bp_tx_routes = extconfig.get('bp_tx_routes', [])

                nodeconf = {
                    'udpcl': {
                        'log_level': 'debug',
                        'bus_addr': 'system',
                        'bus_service': 'org.ietf.dtn.node.udpcl',
                        'node_id': nodeid,

                        'dtls_enable_tx': False,
                        'dtls_ca_file': '/etc/xdg/dtn/ca.crt',
                        'dtls_cert_file': '/etc/xdg/dtn/transport.crt',
                        'dtls_key_file': '/etc/xdg/dtn/transport.key',

                        'polling': extconfig.get('udpcl_polling', []),
                        'init_listen': udpcl_listen,
                    },
                    'tcpcl': {
                        'log_level': 'debug',
                        'bus_addr': 'system',
                        'bus_service': 'org.ietf.dtn.node.tcpcl',
                        'node_id': nodeid,

                        'tls_enable': False,
                        'tls_ca_file': '/etc/xdg/dtn/ca.crt',
                        'tls_cert_file': '/etc/xdg/dtn/transport.crt',
                        'tls_key_file': '/etc/xdg/dtn/transport.key',

                        'init_listen': tcpcl_listen,
                    },
                    'bp': {
                        'log_level': 'debug',
                        'bus_addr': 'system',
                        'bus_service': 'org.ietf.dtn.node.bp',
                        'node_id': nodeid,

                        'verify_ca_file': '/etc/xdg/dtn/ca.crt',
                        'sign_cert_file': '/etc/xdg/dtn/sign.crt',
                        'sign_key_file': '/etc/xdg/dtn/sign.key',

                        'rx_route_table': bp_rx_routes,
                        'tx_route_table': bp_tx_routes,
                        'apps': extconfig.get('apps', {})
                    },
                }
                with open(os.path.join(configPath, 'node.yaml'), 'w') as outfile:
                    outfile.write(yaml.dump(nodeconf))

                cmd = [
                    'container', 'create',
                    '--privileged', '-e', 'container=docker',
                    '--mount', f'type=bind,src={SELFDIR}/workdir/{node_name}/xdg/dtn,dst=/etc/xdg/dtn',
                    '--hostname', fqdn,
                    '--name', node_name,
                ]
                cmd += [img_name_tag]
                self.run_docker(cmd)

                cmd = [
                    'network', 'disconnect',
                    'bridge',
                    node_name
                ]
                self.run_docker(cmd)

                for net_name in node_opts['nets']:
                    cmd = [
                        'network', 'connect',
                        net_name,
                        node_name
                    ]
                    self.run_docker(cmd)

        elif act == 'start':
            for node_name in self._config['nodes'].keys():
                self.run_docker(['container', 'start', node_name])

        elif act == 'stop':
            for node_name in self._config['nodes'].keys():
                try:
                    self.run_docker(['container', 'stop', node_name])
                except subprocess.CalledProcessError:
                    pass

        elif act == 'delete':
            for node_name in self._config['nodes'].keys():
                try:
                    self.run_docker(['container', 'rm', '-f', node_name])
                except subprocess.CalledProcessError:
                    pass
            for net_name in self._config['nets'].keys():
                try:
                    self.run_docker(['network', 'rm', net_name])
                except subprocess.CalledProcessError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
    parser.add_argument('--image-no-cache', default=False, action='store_true')
    parser.add_argument('actions', choices=Runner.ACTIONS, nargs='+')
    args = parser.parse_args()
    LOGGER.debug('args %s', args)

    logging.basicConfig(level=logging.DEBUG)

    # do work in parent directory
    os.chdir(os.path.join(SELFDIR, '..'))

    runner = Runner(args)
    for act in args.actions:
        runner.action(act)


if __name__ == '__main__':
    sys.exit(main())
