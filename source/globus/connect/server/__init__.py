# Copyright 2012-2015 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function, absolute_import

import copy
import logging
import os
import getpass
import pkgutil
import platform
import re
import shutil
import socket
import ssl
import sys
import tempfile
import time

from six.moves.urllib.request import urlopen
from six.moves.urllib.parse import urlparse

from globus_sdk import (
    AccessTokenAuthorizer,
    BasicAuthorizer,
    GlobusAPIError,
    TransferClient)
from globus_sdk.base import BaseClient

import globus.connect.security

from subprocess import Popen, PIPE

LATEST_VERSION_URI = "https://downloads.globus.org/toolkit/gt6/packages/GLOBUS_CONNECT_SERVER_LATEST"

__path__ = pkgutil.extend_path(__path__, __name__)


def _urlopen_with_retries(url, retries=3):
    """retry IOErrors `retries` many times, no wait/sleep"""
    while retries > 1:
        retries -= 1
        try:
            return urlopen(url)
        except IOError:
            pass
    # last time, with no handler
    return urlopen(url)


def to_unicode(data):
    """
    Coerce any string to unicode, assuming utf-8 encoding for strings.
    """
    if sys.version_info < (3,):
        if isinstance(data, unicode):
            return data
        else:
            return unicode(data, 'utf-8')
    else:
        return str(data)

def is_ec2():
    url = 'http://169.254.169.254/latest/meta-data/'
    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = _urlopen_with_retries(url).read().decode('utf8')
    except IOError:
        pass

    if value is not None and re.search(r"404 - (File or directory )*(n|N)ot (f|F)ound", value):
        value = None

    return value is not None

def public_name():
    """
    Try to guess the public host name of this machine. If this is
    on a machine which is able to access ec2 metadata, it will use
    that; otherwise socket.getfqdn()
    """
    url = 'http://169.254.169.254/latest/meta-data/public-hostname'
    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = _urlopen_with_retries(url).read().decode('utf8')
    except IOError:
        pass

    if value is not None and (("404 - Not Found" in value) or value == ""):
        value = None

    if value is None:
        value = socket.getfqdn()
    return value

def public_ip():
    """
    Try to guess the public IP address of this machine. If this is
    on a machine which is able to access ec2 metadata, it will use
    that; otherwise it will return None
    """
    url = 'http://169.254.169.254/latest/meta-data/public-ipv4'

    value = None
    try:
        socket.setdefaulttimeout(3.0)
        value = _urlopen_with_retries(url).read().decode('utf8')
    except IOError:
        pass

    if value is not None and "404 - Not Found" in value:
        value = None

    return value

def is_private_ip(name):
    """
    Determine if a host name resolves to an ip address in a private
    block.
    """
    if re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", name):
        addr = name
    else:
        try:
            addr = socket.gethostbyname(name)
        except Exception as e:
            return True
    octets = [int(x) for x in addr.split(".")]
    return (octets[0] == 10 or \
            (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) or \
            (octets[0] == 192 and octets[1] == 168) or \
            (octets[0] == 127))

def is_local_service(name):
    """
    Determine if a service definition describes a service running on
    the local node. This is true if the service URL is for localhost,
    matches the machine's name, or ec2 public name
    """
    if name is None:
        return False
    if "://" in name:
        url = urlparse.urlparse(name)
        if ":" in url.netloc:
            name = url.netloc.split(":")[0]
        else:
            name = url.netloc
    elif ":" in name:
        name = name.split(":")[0]

    if name == "localhost":
        return True

    if '.' in name:
        name = name.split('.')[0]
    node = socket.getfqdn()
    if '.' in node:
        node = node.split('.')[0]

    if name == node:
        return True
    pn = public_name()
    if pn is not None and pn.split(".")[0] == name:
        return True
    return False

def get_api(conf):
    username = conf.get_go_username()
    if username is None:
        print("Globus Id: ", end=' ')
        username = sys.stdin.readline().strip()
        atglobusidorg = username.rfind("@globusid.org")
        if atglobusidorg != -1:
           username = username[:atglobusidorg]
    password = conf.get_go_password()
    if password is None:
        password = getpass.getpass("Password: ")

    auth_result = None

    go_instance = conf.get_go_instance()
    
    socket.setdefaulttimeout(300)

    GOAUTH_PATH = "/goauth/token?grant_type=client_credentials"

    for tries in range(0,10):
        try:
            authorizer = BasicAuthorizer(username, password)
            nexus_client = BaseClient('nexus', authorizer=authorizer)

            response = nexus_client.get(GOAUTH_PATH)
            access_token = response.data['access_token']
        except GlobusAPIError as e:
            if e.http_status == 403:
                print("{}\nRetrying".format(e.message))
                print("Globus Id: ", end=' ')
                username = sys.stdin.readline().strip()
                password = getpass.getpass("Globus Password: ")
            else:
                raise e
        except ssl.SSLError as e:
            if "timed out" not in str(e):
                raise e
            time.sleep(30)

    if go_instance == 'Production':
        go_instance = 'default'

    class TransferClientWithUserNameAndPassword(TransferClient):
        def __init__(self, username=None, password=None, **kwargs):
            self.username = username
            self.password = password
            super(TransferClientWithUserNameAndPassword, self).__init__(**kwargs)

    api = TransferClientWithUserNameAndPassword(
            username=username,
            password=password,
            authorizer=AccessTokenAuthorizer(access_token),
            environment=go_instance,
            timeout=300.0)

    return api

def is_latest_version(force=False):
    data_version = pkgutil.get_data(
        "globus.connect.server", "version").decode('utf8').strip()

    try:
        published_version = _urlopen_with_retries(
        LATEST_VERSION_URI).read().decode('utf8').strip()
    except IOError as e:
        print("Unable to get version info from: " + LATEST_VERSION_URI + \
              "\n" + str(e) + "\nSkipping version check.", file=sys.stderr)
        return True

    fieldshift = 1000

    data_version_value = 0
    published_version_value = 0

    for field in [int(x) for x in data_version.split(".", 2)]:
        data_version_value = data_version_value * fieldshift + field
    for field in [int(x) for x in published_version.split(".", 2)]:
        published_version_value = published_version_value * fieldshift + field

    if data_version_value < published_version_value:
        message = \
            "A newer version (%s) of globus-connect-server is available.\n" \
            "Please upgrade before running this script (or temporarily use \n" \
            "--force to proceed)." % (published_version)
        if not force:
            raise Exception(message)
        else:
            print("WARNING: " + message, file=sys.stderr)
        return False
    return True
    
class GCMU(object):
    logger = logging.getLogger("globus.connect.server.GCMU")
    handler = logging.StreamHandler()
    logger.addHandler(handler)

    def __init__(self, config_obj, api, debug=False, force=False, **kwargs):
        if config_obj is None:
            raise Exception("Invalid configuration object")
        if api is None:
            raise Exception("Invalid API object")

        self.logger = GCMU.logger
        if debug:
            GCMU.handler.setLevel(logging.DEBUG)
            GCMU.logger.setLevel(logging.DEBUG)
        else:
            GCMU.handler.setLevel(logging.INFO)
            GCMU.logger.setLevel(logging.INFO)
        self.conf = config_obj
        self.debug = debug
        self.force = force
        self.api = api
        self.service = None
        self.cilogon_cas = ['cilogon-basic', 'cilogon-silver']
        self.__myproxy_dn = None
        self.__myproxy_ca_dn = None

        default_dir = os.path.join(self.conf.root, self.conf.DEFAULT_DIR)
        if not os.path.exists(default_dir):
            self.logger.debug("Creating directory: " + default_dir)
            os.makedirs(default_dir, 0o755)

        self.errorcount = 0

    def is_local_gridftp(self):
        server = self.conf.get_gridftp_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_gridftp_server_behind_nat())

    def is_local_myproxy(self):
        server = self.conf.get_myproxy_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_myproxy_server_behind_nat())

    def is_local_oauth(self):
        server = self.conf.get_oauth_server()
        return server is not None and \
            (is_local_service(server) or \
                self.conf.get_oauth_server_behind_nat())

    def configure_credential(self, **kwargs):
        """
        Sets up a service's certificate and private key.

        If configured to use a relay credential, fetch one if there aren't
        already certificate and key files and put them into place. The
        kwarg force=True will force this function to ignore existing key and
        cert files and fetch new ones.

        If not configured to use a relay credential, check whether the
        certificate and key files exist. Warn if they are missing.
        """
        self.logger.debug("ENTER: GCMU.configure_credential()")
        cert = self.conf.get_security_certificate_file()
        key = self.conf.get_security_key_file()
        go_ca3_cert = pkgutil.get_data("globus.connect.security", "go-ca3.pem")
        go_ca3_hash = globus.connect.security.get_certificate_hash_from_data(go_ca3_cert)

        go_ca3_file = os.path.join(
                self.conf.get_security_trusted_certificate_directory(),
                go_ca3_hash)

        if self.conf.get_security_fetch_credential_from_relay():
            if kwargs.get('force') or \
                    (not os.path.exists(cert)) or (not os.path.exists(key)) or \
                    (not os.path.exists(go_ca3_hash + ".0")):
                if os.path.exists(cert):
                    self.logger.debug("Removing old certificate file")
                    os.remove(cert)
                if os.path.exists(key):
                    self.logger.debug("Removing old key file")
                    os.remove(key)

            if (not os.path.exists(cert)) or (not os.path.exists(key)):
                self.logger.debug("Fetching certificate and key from globus")

                result = self.api.post('/private/endpoint_cert','')
                code = result.http_status
                msg = result.text
                j = result.data
                if code != 200:
                    raise Exception("Unable to receive credential: %s %s" % (code, msg))
                self.logger.debug("endpoint_cert_json = " + str(j))
                cert_data = j['cert']
                key_data = j['key']

                for dirname in [os.path.dirname(cert), os.path.dirname(key)]: 
                    if not os.path.exists(dirname):
                        os.makedirs(dirname, 0o755)

                old_umask = os.umask(0o133)
                cfp = open(cert, "w")
                try:
                    self.logger.debug("Writing certificate to disk")
                    cfp.write(cert_data)
                finally:
                    cfp.close()
                os.umask(old_umask)

                old_umask = os.umask(0o177)
                cfp = open(key, "w")
                try:
                    self.logger.debug("Writing key to disk")
                    cfp.write(key_data)
                finally:
                    cfp.close()
                os.umask(old_umask)
        else:
            if not os.path.exists(cert):
                self.logger.warning("Certificate file %s does not exist" 
                    % (cert))
            if not os.path.exists(key):
                self.logger.warning("Key file %s does not exist" % (key))

        self.logger.debug("EXIT: GCMU.configure_credential()")
        return (cert, key)

    def configure_trust_roots(self, **kwargs):
        """
        Configure the certificate trust roots for services. The different
        certificates that may be put into place are:
        - Globus Connect Server CA
        - MyProxy CA
        - CILogon CA

        Also, if the CILogon CA is added to the trust roots, a cronjob
        will be registered to fetch the CRL associated with that CA
        periodically
        """
        self.logger.debug("ENTER: GCMU.configure_trust_roots()")
        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            os.makedirs(certdir, 0o755)

        # Install the Globus Connect Server CA
        gcs_ca_cert = pkgutil.get_data(
                "globus.connect.security",
                "go-ca3.pem").decode('utf8')
        gcs_ca_signing_policy = pkgutil.get_data(
                "globus.connect.security",
                "go-ca3.signing_policy").decode('utf8')
        globus.connect.security.install_ca(
                certdir,
                gcs_ca_cert,
                gcs_ca_signing_policy)

        # Install New Globus Online CA and intermediate CA signing policy
        # if sharing is enabled
        if self.conf.get_gridftp_sharing():
            go_transfer_ca_2_cert = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.pem")
            go_transfer_ca_2_signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.signing_policy")
            globus.connect.security.install_ca(
                    certdir,
                    go_transfer_ca_2_cert,
                    go_transfer_ca_2_signing_policy)
            intermediate_hashes = ['14396025', 'c7ab88a4']
            go_transfer_ca_2_int_signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2_int.signing_policy")
            globus.connect.security.install_signing_policy(
                    go_transfer_ca_2_int_signing_policy,
                    certdir,
                    intermediate_hashes[globus.connect.security.openssl_version()])

        # Install MyProxy CA
        myproxy_server = self.conf.get_myproxy_server()
        if myproxy_server is not None and self.is_local_myproxy():
            # Local myproxy server, just copy the files into location
            if self.conf.get_myproxy_ca():
                myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                myproxy_ca_cert = os.path.join(myproxy_ca_dir, "cacert.pem")
                myproxy_ca_signing_policy = os.path.join(
                        myproxy_ca_dir,
                        "signing-policy")
                globus.connect.security.install_ca(
                    certdir,
                    myproxy_ca_cert,
                    myproxy_ca_signing_policy)
        elif myproxy_server is not None:
            # Remote myproxy server, fetch trust roots from the service
            self.logger.debug("Fetching MyProxy CA trust roots")
            pipe_env = copy.deepcopy(os.environ)
            # If we have valid credential, myproxy will try to use it, but,
            # if the server doesn't trust it there are some errors.
            #
            # We'll make that impossible by setting some environment
            # variables
            pipe_env['X509_CERT_DIR'] = certdir
            pipe_env['X509_USER_CERT'] = ""
            pipe_env['X509_USER_KEY'] = ""
            pipe_env['X509_USER_PROXY'] = ""
            if self.conf.get_myproxy_dn() is not None:
                pipe_env['MYPROXY_SERVER_DN'] = self.conf.get_myproxy_dn()
            else:
                pipe_env['MYPROXY_SERVER_DN'] = \
                        self.get_myproxy_dn_from_server()

            self.logger.debug("fetching trust roots from myproxy server at " + self.conf.get_myproxy_server())
            self.logger.debug("expecting dn " + pipe_env['MYPROXY_SERVER_DN'])
            self.logger.debug("expecting to put them in " + certdir)
            args = [ 'myproxy-get-trustroots', '-b', '-s',
                    self.conf.get_myproxy_server() ]
            myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                env=pipe_env)
            (out, err) = myproxy_bootstrap.communicate()
            if out is not None:
                out = out.decode('utf8')
                self.logger.debug(out)
            if err is not None:
                err = err.decode('utf8')
                self.logger.warn(err)
            if myproxy_bootstrap.returncode != 0:
                self.logger.debug("myproxy bootstrap returned " +
                        str(myproxy_bootstrap.returncode))

            # Correct OpenSSL 0.9.x/1.x hash mismatch
            update_cmd = ['globus-update-certificate-dir', '-d', certdir]
            update = Popen(update_cmd, stdout=None, stderr=None)
            update.communicate()


        # Install CILogon CAs
        if self.conf.get_security_identity_method() == "CILogon":
            for cilogon_ca in self.cilogon_cas:
                cilogon_cert = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".pem")
                cilogon_signing_policy = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".signing_policy")

                globus.connect.security.install_ca(
                    certdir,
                    cilogon_cert,
                    cilogon_signing_policy)

                # Install CILogon update CRL cron job
                cilogon_hash = globus.connect.security.\
                        get_certificate_hash_from_data(cilogon_cert)

                cilogon_crl_script = pkgutil.get_data(
                        "globus.connect.security",
                        "cilogon-crl-fetch")

                cilogon_crl_cron_path = os.path.join(self.conf.root,
                        "etc/cron.hourly",
                        "globus-connect-server-" + cilogon_ca + "-crl")

                cilogon_crl_cron_file = file(cilogon_crl_cron_path, "w")
                try:
                    cilogon_crl_cron_file.write(cilogon_crl_script % {
                        'certdir': certdir,
                        'cilogon_url': 'http://crl.cilogon.org/' + \
                            cilogon_ca + '.r0',
                        'cilogon_hash': cilogon_hash
                    })
                    os.chmod(cilogon_crl_cron_path, 0o755)
                finally:
                    cilogon_crl_cron_file.close()
        self.logger.debug("EXIT: GCMU.configure_trust_roots()")

    def cleanup_trust_roots(self, **kwargs):
        """
        Clean up the certificate trust roots for services. The different
        certificates that may be cleaned up are:
        - Globus Connect Relay CA
        - MyProxy CA
        - CILogon CA

        Also, if the CILogon CA is in the trust roots, remove the CRL
        fetch cronjobs
        """
        self.logger.debug("ENTER: GCMU.cleanup_trust_roots()")
        certdir = self.conf.get_security_trusted_certificate_directory()
        if not os.path.exists(certdir):
            return

        hashes = []
        # Remove Globus Connect Relay CA
        relay_cert = pkgutil.get_data(
                "globus.connect.security",
                "go-ca3.pem")

        hashes.append(globus.connect.security.get_certificate_hash_from_data(
                relay_cert))

        # Install New Globus Online CA and intermediate CA signing policy
        # if sharing is enabled
        if self.conf.get_gridftp_sharing():
            go_transfer_ca_2_cert = pkgutil.get_data(
                    "globus.connect.security",
                    "go_transfer_ca_2.pem")
            hashes.append(
                    globus.connect.security.get_certificate_hash_from_data(
                            go_transfer_ca_2_cert))
            intermediate_hashes = ['14396025', 'c7ab88a4']
            hashes.append(
                    intermediate_hashes[globus.connect.security.openssl_version()])

        # CILogon CAs
        if self.conf.get_security_identity_method() == "CILogon":
            for cilogon_ca in self.cilogon_cas:
                cilogon_cert = pkgutil.get_data(
                        "globus.connect.security",
                        cilogon_ca + ".pem")
                hashes.append(
                        globus.connect.security.get_certificate_hash_from_data(
                                cilogon_cert))
        else: # MyProxy CA
            myproxy_server = self.conf.get_myproxy_server()
            if myproxy_server is not None and self.is_local_myproxy():
                # Local myproxy server, just copy the files into location
                if self.conf.get_myproxy_ca():
                    myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                    myproxy_ca_cert = os.path.join(myproxy_ca_dir, "cacert.pem")
                    try:
                        hashes.append(
                                globus.connect.security.get_certificate_hash(
                                        myproxy_ca_cert))
                    except:
                        pass
            elif myproxy_server is not None:
                # Ugly hack to get what we might have downloaded during install
                # time
                temppath = tempfile.mkdtemp()
                pipe_env = copy.deepcopy(os.environ)
                pipe_env['X509_CERT_DIR'] = temppath
                pipe_env['X509_USER_CERT'] = ""
                pipe_env['X509_USER_KEY'] = ""
                pipe_env['X509_USER_PROXY'] = ""
                if self.conf.get_myproxy_dn() is not None:
                    pipe_env['MYPROXY_SERVER_DN'] = self.conf.get_myproxy_dn()
                else:
                    pipe_env['MYPROXY_SERVER_DN'] = \
                            self.get_myproxy_dn_from_server()
                args = [ 'myproxy-get-trustroots', '-b', '-s',
                        self.conf.get_myproxy_server() ]
                myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                    env=pipe_env)
                (out, err) = myproxy_bootstrap.communicate()
                if out is not None:
                    out = out.decode('utf8')
                    self.logger.debug(out)
                if err is not None:
                    err = err.decode('utf8')
                    self.logger.warn(err)
                if myproxy_bootstrap.returncode != 0:
                    self.logger.debug("myproxy bootstrap returned " +
                            str(myproxy_bootstrap.returncode))
                for entry in os.listdir(temppath):
                    if entry.endswith(".0"):
                        hashes.append(entry.split(".",1)[0])
                shutil.rmtree(temppath, ignore_errors=True)

        for ca_hash in hashes:
            ca_file = os.path.join(certdir, ca_hash + ".0")
            signing_policy_file = os.path.join(
                    certdir,
                    ca_hash+".signing_policy")
            crl_file =  os.path.join(
                    certdir,
                    ca_hash+".r0")
            if os.path.exists(ca_file):
                os.remove(ca_file)
            if os.path.exists(signing_policy_file):
                os.remove(signing_policy_file)
            if os.path.exists(crl_file):
                os.remove(crl_file)

        # Clean dangling links
        for name in os.listdir(certdir):
            link_path = os.path.join(certdir,name)
            if os.path.islink(link_path) and not os.path.exists(link_path):
                os.remove(link_path)

        # CRL Fetch cronjobs
        crondir = os.path.join(self.conf.root, "etc/cron.hourly")
        for cronjob in os.listdir(crondir):
            if cronjob.startswith("globus-connect-server"):
                cronfile = os.path.join(crondir, cronjob)
                if os.path.exists(cronfile):
                    os.remove(cronfile)
        self.logger.debug("EXIT: GCMU.cleanup_trust_roots()")

    def get_myproxy_dn_from_server(self):
        self.logger.debug("ENTER: get_myproxy_dn_from_server()")

        if self.__myproxy_dn is None:
            server_dn = None
            self.logger.debug("fetching myproxy dn from server")
            temppath = tempfile.mkdtemp()

            pipe_env = copy.deepcopy(os.environ)
            # If we have valid credential, myproxy will try to use it, but,
            # if the server doesn't trust it there are some errors.
            #
            # We'll make that impossible by setting some environment
            # variables
            pipe_env['X509_CERT_DIR'] = temppath
            pipe_env['X509_USER_CERT'] = ""
            pipe_env['X509_USER_KEY'] = ""
            pipe_env['X509_USER_PROXY'] = ""

            args = [ 'myproxy-get-trustroots', '-b', '-s',
                    self.conf.get_myproxy_server() ]
            myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                env=pipe_env)
            (out, err) = myproxy_bootstrap.communicate()
            if out is not None:
                out = out.decode('utf8')
            if err is not None:
                err = err.decode('utf8')
            server_dn_match = re.search("New trusted MyProxy server: (.*)", err)
            if server_dn_match is not None:
                server_dn = server_dn_match.groups()[0]
            else:
                server_dn_match = re.search("MYPROXY_SERVER_DN=\"([^\"]*)\"", err)
                if server_dn_match is not None:
                    server_dn = server_dn_match.groups()[0]
            shutil.rmtree(temppath, ignore_errors=True)
            self.logger.debug("MyProxy DN is " + str(server_dn))
            self.__myproxy_dn = server_dn
        self.logger.debug("EXIT: get_myproxy_dn_from_server()")
        return self.__myproxy_dn

    def get_myproxy_ca_dn_from_server(self):
        self.logger.debug("ENTER: get_myproxy_ca_dn_from_server()")

        if self.__myproxy_ca_dn is None:
            server_dn = None
            self.logger.debug("fetching myproxy ca dn from server")
            temppath = tempfile.mkdtemp()

            pipe_env = copy.deepcopy(os.environ)
            # If we have valid credential, myproxy will try to use it, but,
            # if the server doesn't trust it there are some errors.
            #
            # We'll make that impossible by setting some environment
            # variables
            pipe_env['X509_CERT_DIR'] = temppath
            pipe_env['X509_USER_CERT'] = ""
            pipe_env['X509_USER_KEY'] = ""
            pipe_env['X509_USER_PROXY'] = ""

            args = [ 'myproxy-get-trustroots', '-b', '-s',
                    self.conf.get_myproxy_server() ]
            myproxy_bootstrap = Popen(args, stdout=PIPE, stderr=PIPE, 
                env=pipe_env)
            (out, err) = myproxy_bootstrap.communicate()
            if out is not None:
                out = out.decode('utf8')
            if err is not None:
                err = err.decode('utf8')
            server_dn_match = re.search(r"New trusted MyProxy server: (.*)", err)
            server_ca_dn_match = re.search(r"New trusted CA \(([0-9a-f\.]*)\): (.*)", err)
            server_ca_dn = None
            server_dn = None
            if server_ca_dn_match is not None:
                server_ca_dn = server_ca_dn_match.groups()[1]
            if server_dn_match is not None:
                server_dn = server_dn_match.groups()[0]
            if (server_ca_dn is None 
                    or server_ca_dn
                    == '/C=US/O=Globus Consortium/CN=Globus Connect CA' 
                    or server_ca_dn
                    == '/C=US/O=Globus Consortium/CN=Globus Connect CA 3'):
                server_ca_dn = "/O=Globus Connect Server/CN={0}".format(
                    self.conf.get_myproxy_server())
            shutil.rmtree(temppath, ignore_errors=True)
            self.logger.debug("MyProxy CA DN is " + str(server_ca_dn))
            self.__myproxy_ca_dn = server_ca_dn
        self.logger.debug("EXIT: get_myproxy_ca_dn_from_server()")
        return self.__myproxy_ca_dn

    def disable(self, **kwargs):
        service_disable = None

        if service_disable is None:
            systemctl_paths = ["/bin/systemctl", "/usr/bin/systemctl"]
            for systemctl in systemctl_paths:
                if os.path.exists(systemctl):
                    service_disable = [systemctl, "--quiet", "disable",
                            self.service + ".service"]
                    break

        if service_disable is None:
            update_rcd_paths = ["/sbin/update-rc.d", "/usr/sbin/update-rc.d"]
            for update_rcd in update_rcd_paths:
                if os.path.exists(update_rcd):
                    service_disable = [update_rcd, self.service, "disable"]
                    break

        if service_disable is None:
            chkconfig_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
            for chkconfig in chkconfig_paths:
                if os.path.exists(chkconfig):
                    service_disable = [chkconfig, self.service, "off"]
                    break

        if service_disable is not None:
            disabler = Popen(service_disable, stdin=None,
                    stdout=PIPE, stderr=PIPE)
            (out, err) = disabler.communicate()
            if out is not None:
                out = out.decode('utf8')
            if err is not None:
                err = err.decode('utf8')
            if out is not None and out != "" and out != "\n":
                self.logger.debug(out,)
            if err is not None and err != "" and err != "\n":
                if disabler.returncode != 0:
                    self.logger.warn(err,)
                else:
                    self.logger.debug(err,)

    def enable(self, **kwargs):
        service_enable = None

        if service_enable is None:
            systemctl_paths = ["/bin/systemctl", "/usr/bin/systemctl"]
            for systemctl in systemctl_paths:
                if os.path.exists(systemctl):
                    service_enable = [systemctl, "--quiet", "enable",
                            self.service + ".service"]
                    break

        if service_enable is None:
            update_rcd_paths = ["/sbin/update-rc.d", "/usr/sbin/update-rc.d"]
            for update_rcd in update_rcd_paths:
                if os.path.exists(update_rcd):
                    service_enable = [update_rcd, self.service, "enable"]
                    break

        if service_enable is None:
            chkconfig_paths = ["/sbin/chkconfig", "/usr/sbin/chkconfig"]
            for chkconfig in chkconfig_paths:
                if os.path.exists(chkconfig):
                    service_enable = [chkconfig, self.service, "on"]
                    break

        if service_enable is not None:
            enabler = Popen(service_enable, stdin=None,
                    stdout=PIPE, stderr=PIPE)
            (out, err) = enabler.communicate()
            if out is not None:
                out = out.decode('utf8')
            if err is not None:
                err = err.decode('utf8')
            if out is not None and out != "" and out != "\n":
                self.logger.debug(out,)
            if err is not None and err != "" and err != "\n":
                if enabler.returncode != 0:
                    self.logger.warn(err,)
                else:
                    self.logger.debug(err,)

    def stop(self, **kwargs):
        (name, ver, id) = platform.linux_distribution()
        args = ["/etc/init.d/" + self.service, "stop"]

        if name.startswith('CentOS') \
                or name == 'RedHat' \
                or name.startswith('Red Hat') \
                or name.startswith("Scientific") \
                or name == 'Fedora' \
                or name.startswith("SUSE"):
            if os.path.exists("/bin/systemctl"):
                args = ["/bin/systemctl", "stop", self.service]
            else:
                args = ["/sbin/service", self.service, "stop"]
        elif name == 'Ubuntu' or name == 'Debian':
            if os.path.exists("/bin/systemctl"):
                args = ["/bin/systemctl", "stop", self.service]
            else:
                args = ["/usr/sbin/service", self.service, "stop"]

        stopper = Popen(args, stdin = None, stdout=PIPE, stderr=PIPE)
        stopper.communicate()
                    

    def restart(self, **kwargs):
        self.logger.debug("ENTER: GCMU.restart()")
        (name, ver, id) = platform.linux_distribution()
        args = ["/etc/init.d/" + self.service, "restart"]

        if name.startswith('CentOS') \
                or name == 'RedHat' \
                or name.startswith('Red Hat') \
                or name.startswith("Scientific") \
                or name == 'Fedora' \
                or name.startswith("SUSE"):
            if os.path.exists("/bin/systemctl"):
                args = ["/bin/systemctl", "restart", self.service]
            else:
                args = ["/sbin/service", self.service, "restart"]
        elif name == 'Ubuntu' or name == 'Debian':
            if os.path.exists("/bin/systemctl"):
                args = ["/bin/systemctl", "restart", self.service]
            else:
                args = ["/usr/sbin/service", self.service, "restart"]

        self.logger.debug("restarting with " + " ".join(args))
        restarter = Popen(args, stdin = None, stdout=PIPE, stderr=PIPE)
        restarter.communicate()
        self.logger.debug("EXIT: GCMU.restart()")
                    
# vim: filetype=python: nospell:
