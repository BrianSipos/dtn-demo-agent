#!/usr/bin/env python3
''' An orchestrator for starting networks within containers.

The directory ./workdir is used as a test file staging area.
'''

import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import asn1
import datetime
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Union, Optional
import yaml

LOGGER = logging.getLogger()
SELFDIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_STAGEDIR = os.path.join(SELFDIR, 'workdir')


class PkiCa:
    ''' A local software PKI CA generator. '''

    def __init__(self):
        self._nowtime = datetime.datetime.now(datetime.timezone.utc)
        self._ca_key = None
        self._ca_cert = None

    def other_name_eid(self, eid: str) -> x509.OtherName:
        ''' Encode a text EID as an Other Name object.
        '''
        eid_enc = asn1.Encoder()
        eid_enc.start()
        eid_enc.write(eid.encode('ascii'), asn1.Numbers.IA5String)
        return x509.OtherName(
            x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.8.11'),  # id-on-bundleEID
            eid_enc.output()
        )

    def generate_key(self, key_opts: dict) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        keytype = key_opts.get('keytype', 'SECP256R1').upper()
        if keytype == 'RSA':
            key_size = 2048
            node_key = rsa.generate_private_key(65537, key_size, backend=default_backend())
        elif keytype.startswith('SECP'):
            curve = getattr(ec, keytype)
            node_key = ec.generate_private_key(curve(), backend=default_backend())  # Curve for COSE ES256
        else:
            raise ValueError(f'Unknown keytype: {keytype}')
        return node_key

    def generate_root_ca(self, certfile: str, keyfile: str) -> x509.Certificate:
        ''' Generate and retain a root CA. '''
        ca_key = self.generate_key({})

        ca_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Certificate Authority'),
        ])
        ca_cert = x509.CertificateBuilder().subject_name(
            ca_name
        ).issuer_name(
            ca_name
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            self._nowtime
        ).not_valid_after(
            self._nowtime + datetime.timedelta(days=10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            # This is mandated by some browser interpretations of chain validation
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
            ]),
            critical=False,
        ).add_extension(
            x509.NameConstraints(
                permitted_subtrees=[
                    self.other_name_eid('ipn:*.*'),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())

        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'wb') as outfile:
            outfile.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.makedirs(os.path.dirname(certfile), exist_ok=True)
        with open(certfile, 'wb') as outfile:
            outfile.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        self._ca_key = ca_key
        self._ca_cert = ca_cert

    def generate_end_entity(self, cafile: str, certfile: str, keyfile: str, mode: str, nodeid: str, fqdn: Optional[str] = None) -> x509.Certificate:
        '''
        :param mode: Either 'transport' or 'signing'.
        :param nodeid: The Node ID for the entity as a URI string.
        :param fqdn: For transport mode, the FQDN of the node.
        '''

        sans = [
            self.other_name_eid(nodeid)
        ]
        key_usage = dict(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        ekus = [
            x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
        ]

        node_key = self.generate_key({})

        if mode == 'transport':
            sans += [
                x509.DNSName(fqdn),
            ]
            key_usage['digital_signature'] = True
            ekus += [
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        elif mode == 'signing':
            key_usage['digital_signature'] = True
        elif mode == 'encryption':
            key_usage['key_agreement'] = True

        node_cert = x509.CertificateBuilder().subject_name(
            # no name
        ).issuer_name(
            self._ca_cert.subject
        ).public_key(
            node_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            self._nowtime
        ).not_valid_after(
            self._nowtime + datetime.timedelta(days=10)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=True,
        ).add_extension(
            x509.KeyUsage(**key_usage),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage(ekus),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
            critical=False,
        ).sign(self._ca_key, hashes.SHA256(), backend=default_backend())

        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'wb') as outfile:
            outfile.write(node_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.makedirs(os.path.dirname(certfile), exist_ok=True)
        with open(certfile, 'wb') as outfile:
            outfile.write(node_cert.public_bytes(serialization.Encoding.PEM))
        if cafile:
            os.makedirs(os.path.dirname(cafile), exist_ok=True)
            with open(cafile, 'wb') as outfile:
                outfile.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))


def _runcmd(parts, **kwargs):
    LOGGER.info('Running command %s', ' '.join(f'"{part}"' for part in parts))
    return subprocess.run(parts, **kwargs)


class Docker:

    def __init__(self, stage_dir):
        self._docker = re.split(r'\s+', os.environ.get('DOCKER', 'docker').strip())
        self.composefile = os.path.join(stage_dir, 'docker-compose.yml')

    def run_docker(self, args, **kwargs):
        env = os.environ
        env.update({
            'DOCKER_BUILDKIT': '1',
        })
        kwargs.setdefault('env', env)
        kwargs.setdefault('check', True)
        return _runcmd(self._docker + args, **kwargs)

    def run_docker_compose(self, args, **kwargs):
        env = os.environ
        env.update({
            'DOCKER_BUILDKIT': '1',
        })
        kwargs.setdefault('env', env)
        kwargs.setdefault('check', True)
        filepart = ['compose', '-f', self.composefile, '-p', 'demo']
        return _runcmd(self._docker + filepart + args, **kwargs)

    def run_exec(self, args, **kwargs):
        kwargs.setdefault('check', False)
        return self.run_docker_compose(['exec'] + args, **kwargs)


_ACTIONS = list()
''' Available actions correspond to public functions '''


@staticmethod
def action(func):
    _ACTIONS.append(func.__name__)
    return func


class Runner:
    def __init__(self, args):
        self.args = args

        self._stagedir = args.stage_dir
        if not os.path.exists(self._stagedir):
            os.makedirs(self._stagedir)

        self._docker = Docker(stage_dir=self._stagedir)

        with open(args.config, 'rb') as conffile:
            self._config = yaml.safe_load(conffile)

    # Action methods follow

    @action
    def pkigen(self):
        pca = PkiCa()

        cadir = os.path.join(self._stagedir, 'ca')
        os.makedirs(cadir, exist_ok=True)
        pca.generate_root_ca(
            certfile=os.path.join(cadir, 'cert.pem'),
            keyfile=os.path.join(self._stagedir, 'ca', 'key.pem')
        )

        for (node_name, node_opts) in self._config['nodes'].items():
            ipn_node = node_opts.get('ipn_node')
            nodeid = f'ipn:{ipn_node}.0' if ipn_node else 'dtn://{}/'.format(node_name)

            # Ubuntu common path mounted to /etc/ssl/
            nodedir = os.path.join(self._stagedir, 'nodes', node_name, 'ssl')

            pca.generate_end_entity(
                cafile=os.path.join(nodedir, 'certs', 'ca.crt'),
                certfile=os.path.join(nodedir, 'certs', 'node-sign.crt'),
                keyfile=os.path.join(nodedir, 'private', 'node-sign.pem'),
                mode='signing',
                nodeid=nodeid
            )
            pca.generate_end_entity(
                cafile=None,
                certfile=os.path.join(nodedir, 'certs', 'node-encrypt.crt'),
                keyfile=os.path.join(nodedir, 'private', 'node-encrypt.pem'),
                mode='encryption',
                nodeid=nodeid
            )

            extconfig = node_opts.get('config', {})
            tls_enable = extconfig.get('tls_enable', False)
            dtls_enable = extconfig.get('dtls_enable_tx', False)
            if tls_enable or dtls_enable:
                fqdn = node_name + '.local'
                pca.generate_end_entity(
                    cafile=None,
                    certfile=os.path.join(nodedir, 'certs', 'node-transport.crt'),
                    keyfile=os.path.join(nodedir, 'private', 'node-transport.pem'),
                    mode='transport',
                    nodeid=nodeid,
                    fqdn=fqdn,
                )

    @action
    def build(self):
        compose = {
            'networks': {},
            'services': {},
        }

        for (net_name, net_opts) in self._config['nets'].items():
            ipam_config = []
            if 'subnet4' in net_opts:
                ipam_config.append({
                    'subnet': net_opts['subnet4'],
                })
            if 'subnet6' in net_opts:
                ipam_config.append({
                    'subnet': net_opts['subnet6'],
                })

            compose['networks'][net_name] = {
                'driver': 'bridge',
                'driver_opts': {
                    'com.docker.network.bridge.name': f'br-{net_name}',
                    'com.docker.network.container_iface_prefix': net_name,
                    'com.docker.network.driver.mtu': net_opts.get('mtu', 1500),
                },
                'enable_ipv6': ('subnet6' in net_opts),
                'ipam': {
                    'config': ipam_config,
                },
            }

        for (node_name, node_opts) in self._config['nodes'].items():
            fqdn = node_name + '.local'

            node_serv = {
                'container_name': node_name,
                'hostname': node_name,
                'privileged': True,
                'cap_add': [
                    'NET_ADMIN',
                    'NET_RAW',
                    'SYS_NICE',
                ],
                'environment': [
                    'container=docker',
                    'SSLKEYLOGFILE=/var/log/dtn/tlskeylog',
                ],
                'deploy': {
                    'resources': {
                        'limits': {
                            'memory': '256M',
                        },
                    },
                },
                'volumes': [
                    {
                        'type': 'bind',
                        'source': os.path.join(self._stagedir, 'nodes', node_name, 'ssl'),
                        'target': '/etc/ssl',
                        'read_only': True,
                    },
                    {
                        'type': 'bind',
                        'source': os.path.join(self._stagedir, 'nodes', node_name, 'xdg', 'dtn'),
                        'target': '/etc/xdg/dtn',
                        'read_only': True,
                    },
                    {
                        'type': 'bind',
                        'source': os.path.join(self._stagedir, 'nodes', node_name, 'log'),
                        'target': '/var/log/dtn',
                    },
                ],
                'networks': [net_name for net_name in node_opts['nets']],
            }

            node_serv['build'] = {
                'context': os.path.dirname(SELFDIR),  # parent
                'dockerfile': os.path.join(SELFDIR, 'Dockerfile'),
                # 'target': 'dtn-demo-agent',
            }

            config_path = os.path.join(self._stagedir, 'nodes', node_name, 'xdg', 'dtn')
            os.makedirs(config_path, exist_ok=True)

            log_path = os.path.join(self._stagedir, 'nodes', node_name, 'log')
            os.makedirs(log_path, exist_ok=True)

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
                                'addr': '224.0.1.20',
                            },
                        ],
                    })
                if use_ipv6:
                    udpcl_listen.append({
                        'address': '::',
                        'multicast_member': [
                            {
                                'addr': 'FF05::114',
                                'iface': f'{net_name}0',
                            }
                            for net_name in node_opts['nets']
                        ],
                    })

            tcpcl_listen = []
            if extconfig.get('tcpcl_listen', True):
                if use_ipv4 and not use_ipv6:
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
                    'eid_pattern': f'dtn://{node_name}/.*',
                    'action': 'deliver',
                },
                {
                    'eid_pattern': '.*',
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

                    'dtls_enable_tx': extconfig.get('dtls_enable_tx', False),
                    'dtls_ca_file': '/etc/ssl/certs/ca.crt',
                    'dtls_cert_file': '/etc/ssl/certs/node-transport.crt',
                    'dtls_key_file': '/etc/ssl/private/node-transport.pem',

                    'polling': extconfig.get('udpcl_polling', []),
                    'init_listen': udpcl_listen,
                },
                'tcpcl': {
                    'log_level': 'debug',
                    'bus_addr': 'system',
                    'bus_service': 'org.ietf.dtn.node.tcpcl',
                    'node_id': nodeid,

                    'tls_enable': extconfig.get('tls_enable', False),
                    'tls_ca_file': '/etc/ssl/certs/ca.crt',
                    'tls_cert_file': '/etc/ssl/certs/node-transport.crt',
                    'tls_key_file': '/etc/ssl/private/node-transport.pem',

                    'init_listen': tcpcl_listen,
                },
                'bp': {
                    'log_level': 'debug',
                    'bus_addr': 'system',
                    'bus_service': 'org.ietf.dtn.node.bp',
                    'node_id': nodeid,

                    'verify_ca_file': '/etc/ssl/certs/ca.crt',
                    'sign_cert_file': '/etc/ssl/certs/node-sign.crt',
                    'sign_key_file': '/etc/ssl/private/node-sign.pem',

                    'rx_route_table': bp_rx_routes,
                    'tx_route_table': bp_tx_routes,
                    'apps': extconfig.get('apps', {})
                },
            }
            with open(os.path.join(config_path, 'node.yaml'), 'w') as outfile:
                outfile.write(yaml.dump(nodeconf))

            # All done with this node
            compose['services'][node_name] = node_serv

        with open(self._docker.composefile, 'w') as outfile:
            yaml.dump(compose, outfile, sort_keys=False)

        self._docker.run_docker_compose(['build'])

    @action
    def create(self):
        self._docker.run_docker_compose(['create', '--force-recreate', '--remove-orphans'])

    @action
    def start(self):
        self._docker.run_docker_compose(['up', '-d'])

    @action
    def ready(self):
        ''' Wait for services to be ready '''
        for name, node in self._config['nodes'].items():
            serv_name = 'dtn-bp-agent@node'

            args = ['-T', name, 'systemctl', 'is-active', '-q', serv_name]
            while True:
                time.sleep(1)
                try:
                    self._docker.run_exec(args, check=True)
                    break
                except Exception as err:
                    continue

    @action
    def check_sand(self):
        # limit number of checks
        for _ix in range(10):
            least = None
            for node_name in self._config['nodes'].keys():
                comp = self._docker.run_exec(['-T', node_name, 'journalctl', '--unit=dtn-bp-agent@node'], capture_output=True, text=True)
                got = comp.stdout.count('Verified BIB target block num 1')
                if least is None or got < least:
                    least = got
            LOGGER.info('Least number of verified BIBs: %s', least)
            if least >= 3:
                return
            time.sleep(3)

        for node_name in self._config['nodes'].keys():
            self._docker.run_exec(['-T', node_name, 'journalctl', '--unit=dtn-bp-agent@node'])
        raise RuntimeError('Did not see at least 3 verified BIBs')

    @action
    def stop(self):
        self._docker.run_docker_compose(['down'])

    @action
    def delete(self):
        self._docker.run_docker_compose(['rm', '-sf'])

    def do_exec(self):
        self._docker.run_exec([self.args.container] + self.args.args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level',
                        metavar='LEVEL',
                        default='INFO',
                        help='Console logging lowest severity.')
    parser.add_argument('--config', type=str, required=True,
                        help='The scenario YAML file to load',
                        )
    parser.add_argument('--image-no-cache', default=False, action='store_true')
    parser.add_argument('--stage-dir', default=DEFAULT_STAGEDIR,
                        help='The staging file path'
                        )
    subparsers = parser.add_subparsers(
        dest='top_action',
        help='The top action to perform',
    )
    sub_exec = subparsers.add_parser('exec',
                                     help='Execute within a container')
    sub_exec.add_argument('container',
                          help='Name of container to execute on')
    sub_exec.add_argument('args', nargs='+',
                          help='Command and its arguments to execute')
    sub_act = subparsers.add_parser('act', help='Perform one or more action')
    sub_act.add_argument('actions', choices=_ACTIONS, nargs='+')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    LOGGER.debug('args %s', args)

    # do work in parent directory
    os.chdir(os.path.join(SELFDIR, '..'))

    runner = Runner(args)
    if args.top_action == 'act':
        for act in args.actions:
            func = getattr(runner, act)
            func()
    elif args.top_action == 'exec':
        runner.do_exec()


if __name__ == '__main__':
    sys.exit(main())
