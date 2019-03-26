#! /usr/bin/python

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

import os
import pkgutil
import platform

import globus.connect.security as security
import globus.connect.server as gcmu

from six.moves import urllib_parse

from globus_sdk import GlobusAPIError

class IO(gcmu.GCMU):
    """
    Class to configure a GridFTP server and register it as a Globus
    endpoint
    """
    def __init__(self, **kwargs):
        super(IO, self).__init__(**kwargs)
        self.etc_gridftp_d = self.conf.get_etc_gridftp_d()
        self.var_gridftp_d = self.conf.get_var_gridftp_d()
        self.logrotate_d = os.path.join(self.conf.root, "etc", "logrotate.d")
        self.logrotate_path = os.path.join(self.logrotate_d,
                "globus-connect-server")
        self.service = "globus-gridftp-server"
        self.endpoint_id_file = self.conf.get_endpoint_id_file()
        if os.path.exists(self.endpoint_id_file):
            with open(self.endpoint_id_file, 'r') as f:
                self.endpoint_xid = f.read().strip()
        else:
            self.endpoint_xid = ''

        if self.endpoint_xid == '':
            self.endpoint_xid = urllib_parse.quote(
                self.conf.get_endpoint_name())

        if not os.path.exists(self.etc_gridftp_d):
            os.makedirs(self.etc_gridftp_d, 0o755)
        if not os.path.exists(self.var_gridftp_d):
            os.makedirs(self.var_gridftp_d, 0o755)

    def is_local(self):
        return self.is_local_gridftp()

    def setup(self, **kwargs):
        self.logger.debug("ENTER: IO.setup()")

        if not self.is_local():
            self.logger.debug("No GridFTP server to configure on this node")
            return

        self.configure_credential(**kwargs)
        self.configure_server(**kwargs)
        self.configure_sharing(**kwargs)
        self.configure_trust_roots(**kwargs)
        self.configure_authorization(**kwargs)
        self.configure_logging(**kwargs)
        self.restart(**kwargs)
        self.enable(**kwargs)
        self.bind_to_endpoint(**kwargs)
        print("Configured GridFTP server to run on " \
            + self.conf.get_gridftp_server())
        print("Server DN: " + security.get_certificate_subject(
                self.conf.get_security_certificate_file()))
        print("Using Authentication Method " + \
            self.conf.get_security_identity_method())
        print("Configured Endpoint " + self.endpoint_xid)
        self.logger.debug("EXIT: IO.setup()")

    def configure_credential(self, **kwargs):
        """
        Sets up a GridFTP server's certificate and private key.

        Writes a GridFTP configuration fragment to set the certificate and
        key paths in the GridFTP server's environment.
        """
        self.logger.debug("ENTER: IO.configure_credential()")

        (cert, key) = super(IO, self).configure_credential(**kwargs)

        cred_config_file = os.path.join(
                self.var_gridftp_d,
                "globus-connect-server-credential")
        cred_config = open(cred_config_file, "w")

        link_name = os.path.join(
                self.etc_gridftp_d,
                "globus-connect-server-credential")

        if os.path.lexists(link_name):
            os.remove(link_name)

        try:
            try:
                self.logger.debug("Writing GridFTP credential configuration")
                cred_config.write("$X509_USER_CERT \"%s\"\n" % (cert))
                cred_config.write("$X509_USER_KEY \"%s\"\n" % (key))
            except:
                self.logger.error("Error writing GridFTP credential config")
        finally:
            cred_config.close()

        try:
            os.symlink(cred_config_file, link_name)
        except:
            self.logger.error("ERROR creating symlink to GridFTP " +
                    "credential config")

        self.logger.debug("EXIT: IO.configure_credential()")

    def configure_server(self, **kwargs):
        """
        Write a configuration file containing the general GridFTP configuration
        items from the configuration file: IncomingPortRange,
        OutgoingPortRange, DataInterface, and RestrictPaths
        """
        self.logger.debug("ENTER: configure_server()")
        server = self.conf.get_gridftp_server()
        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-server")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-server")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        self.logger.debug("Creating gridftp configuration")

        conf_file = file(conf_file_name, "w")
        try:
            dist = platform.dist()
            arch = platform.architecture()
            dist_string_parts = []
            if dist[0] != "":
                dist_string_parts.append(dist[0])
            if dist[1] != "":
                dist_string_parts.append(dist[1])
            if arch[0] != "":
                dist_string_parts.append(arch[0])
            dist_string = "-".join(dist_string_parts)
            version = pkgutil.get_data(
                "globus.connect.server",
                "version")
            if version:
                version = version.strip()
                conf_file.write("version_tag GCS-%s\n" % (version))
                if dist_string != "":
                    conf_file.write("usage_stats_id GCS-%s+%s\n" % (version, dist_string))
                else:
                    conf_file.write("usage_stats_id GCS-%s\n" % (version))
            if ":" in server:
                port = int(server.split(":")[1])
                conf_file.write("port %d\n" % port)
                self.logger.warn(
"""
******************************************************************************
WARNING: You configured your GridFTP server with a custom port.  In order
to override the default GridFTP server port, it may be necessary to edit
the global GridFTP server configuration file at /etc/gridftp.conf, and
comment out the "port" argument.
Change:
port 2811
to
#port 2811

Restart the globus-gridftp-server service if changes are made.
******************************************************************************
""")
            incoming_range = self.conf.get_gridftp_incoming_port_range()
            if incoming_range is not None:
                conf_file.write(
                    "port_range %d,%d\n" \
                    % (incoming_range[0], incoming_range[1]))
            outgoing_range = self.conf.get_gridftp_outgoing_port_range()
            if outgoing_range is not None:
                conf_file.write("$GLOBUS_TCP_SOURCE_RANGE %d,%d\n" \
                    % (outgoing_range[0], outgoing_range[1]))
            data_interface = self.conf.get_gridftp_data_interface()

            if data_interface is None:
                if gcmu.is_ec2():
                    data_interface = gcmu.public_ip()
                elif self.conf.get_gridftp_server_behind_nat():
                    data_interface = server
                    if ":" in data_interface:
                        data_interface = data_interface.split(":")[0]
                    if gcmu.is_private_ip(data_interface):
                        self.logger.warn(
"""
******************************************************************************
WARNING: Your GridFTP server is behind a NAT, but the Server name resolves
to a private IP address. This probably won't work correctly with Globus.
To remedy, set the DataInterface option in the [GridFTP] section of the
globus-connect-server.conf file to the public IP address of this GridFTP
server
******************************************************************************
""")

            if data_interface is not None:
                conf_file.write("data_interface %s\n" \
                    % (data_interface))

            rp = self.conf.get_gridftp_restrict_paths()
            if rp is not None:
                conf_file.write("restrict_paths %s\n" % rp)

            rps = self.conf.get_gridftp_restrict_paths_symlinks()
            if rps is not None:
                conf_file.write("rp_symlinks %s\n" % rps)

            if self.conf.get_gridftp_udt():
               conf_file.write("allow_udt 1\n")
               conf_file.write("threads 1\n")

            if self.conf.get_gridftp_encrypt():
                conf_file.write("encrypt_data 1\n")

            extra_arg = self.conf.get_gridftp_extra_arg()
            if extra_arg is not None:
               conf_file.write(extra_arg + "\n")

            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_server()")

    def configure_sharing(self, **kwargs):
        """
        Write GridFTP sharing-related configuration items. These are written
        only if Sharing is True in the configuration file. The configuration
        parameters SharingDN, SharingRestrictPaths, SharingUsersAllow, 
        SharingUsersDeny, SharingGroupsAllow, SharingGroupsDeny, and 
        SharingStateDir are
        processed here
        """
        self.logger.debug("ENTER: IO.configure_sharing()")

        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-server-sharing")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-server-sharing")

        if os.path.lexists(conf_link_name):
            self.logger.debug("Removing old sharing configuration link")
            os.remove(conf_link_name)

        if not self.conf.get_gridftp_sharing():
            if os.path.exists(conf_file_name):
                self.logger.debug("Removing old sharing configuration file")
                os.remove(conf_file_name)
            self.logger.debug("GridFTP Sharing Disabled")
            return

        conf_file = file(conf_file_name, "w")
        try:
            sharing_dn = self.conf.get_gridftp_sharing_dn()
            conf_file.write("sharing_dn\t\"%s\"\n" % \
                sharing_dn)
            sharing_rp = self.conf.get_gridftp_sharing_restrict_paths()
            if sharing_rp is not None:
                conf_file.write("sharing_rp %s\n" % sharing_rp)
            sharing_dir = self.conf.get_gridftp_sharing_state_dir()
            if sharing_dir is not None:
                conf_file.write("sharing_state_dir %s\n" % sharing_dir)
            sharing_users_allow = self.conf.get_gridftp_sharing_users_allow()
            if sharing_users_allow is not None:
                conf_file.write("sharing_users_allow %s\n" % sharing_users_allow)
            sharing_users_deny = self.conf.get_gridftp_sharing_users_deny()
            if sharing_users_deny is not None:
                conf_file.write("sharing_users_deny %s\n" % sharing_users_deny)
            sharing_groups_allow = self.conf.get_gridftp_sharing_groups_allow()
            if sharing_groups_allow is not None:
                conf_file.write("sharing_groups_allow %s\n" % sharing_groups_allow)
            sharing_groups_deny = self.conf.get_gridftp_sharing_groups_deny()
            if sharing_groups_deny is not None:
                conf_file.write("sharing_groups_deny %s\n" % sharing_groups_deny)
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_sharing()")

    def configure_trust_roots(self, **kwargs):
        """
        Configure the GridFTP server to use the trust roots needed to
        match the definition in the security section of the configuration.
        """
        self.logger.debug("ENTER: IO.configure_trust_roots()")
        # The setup class will populate the trusted CA dir, this class
        # adds the gridftp-specific configuration
        super(IO, self).configure_trust_roots(**kwargs)
        cadir = self.conf.get_security_trusted_certificate_directory()

        conf_file_name = os.path.join(
                self.var_gridftp_d, "globus-connect-server-trust-roots")
        conf_link_name = os.path.join(
                self.etc_gridftp_d, "globus-connect-server-trust-roots")

        if os.path.lexists(conf_link_name):
            self.logger.debug("Removing old trust roots configuration link")
            os.remove(conf_link_name)

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("$X509_CERT_DIR \"%s\"\n" % (cadir))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: IO.configure_sharing()")


    def configure_authorization(self, **kwargs):
        method = self.conf.get_security_authorization_method()

        conf_file_name = os.path.join(
                self.var_gridftp_d,
                "globus-connect-server-authorization")
        conf_link_name = os.path.join(
                self.etc_gridftp_d,
                "globus-connect-server-authorization")
        server = self.conf.get_gridftp_server()

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        if method == "MyProxyGridmapCallout":
            return self.configure_gridmap_verify_myproxy_callout(
                    conf_file_name, conf_link_name, **kwargs)
        elif method == "CILogon":
            return self.configure_cilogon(
                    conf_file_name, conf_link_name, **kwargs)
        elif method == "Gridmap":
            return self.configure_gridmap(
                    conf_file_name, conf_link_name, **kwargs)

    def configure_logging(self, **kwargs):
        conf_file_name = os.path.join(
                self.var_gridftp_d,
                "globus-connect-server-gridftp-logging")
        conf_link_name = os.path.join(
                self.etc_gridftp_d,
                "globus-connect-server-gridftp-logging")

        if os.path.lexists(conf_link_name):
            os.remove(conf_link_name)

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("log_single /var/log/gridftp.log\n")
            conf_file.write("log_level ERROR,WARN\n")
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()

        if os.path.lexists(self.logrotate_path):
            os.remove(self.logrotate_path)

        logrotate_file = file(self.logrotate_path, "w")
        try:
            logrotate_file.write("/var/log/gridftp.log {\n")
            logrotate_file.write("   rotate 4\n")
            logrotate_file.write("   weekly\n")
            logrotate_file.write("   missingok\n")
            logrotate_file.write("   compress\n")
            logrotate_file.write("   create 644 root root\n")
            logrotate_file.write("   postrotate\n")
            logrotate_file.write("       kill -HUP `cat /var/run/globus-gridftp-server.pid`\n")
            logrotate_file.write("   endscript\n")
            logrotate_file.write("}\n")
        finally:
            logrotate_file.close()
        self.logger.debug("EXIT: IO.configure_logging()")

    def configure_gridmap_verify_myproxy_callout(self, conf_file_name, conf_link_name, **kwargs):
        self.logger.debug("ENTER: configure_gridmap_verify_myproxy_callout()")

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("$GSI_AUTHZ_CONF \"%s\"\n" % (
                os.path.join(
                    self.conf.root, "etc",
                    "gridmap_verify_myproxy_callout-gsi_authz.conf"
                    )
                )
            )
            conf_file.write("$GRIDMAP \"%s\"\n" %(
                self.conf.get_security_gridmap()))
            myproxy_certpath = None
            myproxy_signing_policy = None
            myproxy_ca_dn = self.conf.get_myproxy_ca_subject_dn()
            myproxy_server = self.conf.get_myproxy_server()
            if myproxy_ca_dn is None and myproxy_server is not None:
                if self.is_local_myproxy():
                    myproxy_ca_dir = self.conf.get_myproxy_ca_directory()
                    myproxy_ca_dn = security.get_certificate_subject(
                            os.path.join(myproxy_ca_dir, "cacert.pem"))
                else:
                    myproxy_ca_dn = self.get_myproxy_ca_dn_from_server()
                if myproxy_ca_dn is None:
                    # Assume the CA name is the same as the MyProxy server's
                    # subject
                    myproxy_ca_dn = self.conf.get_myproxy_dn()
                    if myproxy_ca_dn is None:
                        myproxy_ca_dn = self.get_myproxy_dn_from_server()

            cadir = self.conf.get_security_trusted_certificate_directory()
            self.logger.debug("MyProxy CA DN is " + str(myproxy_ca_dn))
            self.logger.debug("CA dir is " + str(cadir))

            if self.is_local_myproxy():
                myproxy_certpath = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "cacert.pem")
                myproxy_signing_policy = os.path.join(
                    self.conf.get_myproxy_ca_directory(),
                    "signing-policy")
            elif myproxy_ca_dn is not None:
                self.logger.debug("Looking for MyProxy CA cert in " + cadir)
                for certfile in os.listdir(cadir):
                    certpath = os.path.join(cadir, certfile)
                    if certfile[-2:] == '.0':
                        self.logger.debug("Checking to see if " + certfile + " matches MyProxyDN")
                        if security.get_certificate_subject(
                                certpath) == myproxy_ca_dn:
                            myproxy_certpath = certpath
                            (myproxy_signing_policy, _) = \
                                    os.path.splitext(
                                            myproxy_certpath)
                            myproxy_signing_policy += \
                                    ".signing_policy"
                            break

            if myproxy_certpath is None:
                raise Exception("ERROR: Unable to determine " +
                    "path to MyProxy CA certificate, set " + \
                    "CaCert option in MyProxy section of config.\n")

            myproxy_ca_hash = security.get_certificate_hash(
                    myproxy_certpath)
                    
            cadir = \
                self.conf.get_security_trusted_certificate_directory()
            installed_cert = os.path.join(
                    cadir, myproxy_ca_hash + ".0")
            installed_signing_policy = os.path.join(
                    cadir, myproxy_ca_hash + ".signing_policy")
            if not os.path.exists(installed_cert):
                self.logger.error("MyProxy CA not installed in trusted CA dir")
            if not os.path.exists(installed_signing_policy):
                self.logger.error("MyProxy CA signing policy not installed " + \
                    "in trusted CA dir")
            
            conf_file.write(
                    "$GLOBUS_MYPROXY_CA_CERT \"%s\"\n" %
                    installed_cert)
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: configure_gridmap_verify_myproxy_callout()")

    def configure_cilogon(self, conf_file_name, conf_link_name, **kwargs):
        self.logger.debug("ENTER: IO.configure_cilogon()")

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write(
                    "$GSI_AUTHZ_CONF \"%s\"\n" % self.conf.get_authz_config_file())
            conf_file.write("$GRIDMAP \"%s\"\n" %(
                self.conf.get_security_gridmap()))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
            
        conf_file = file(self.conf.get_authz_config_file(), "w")
        try:
            cadir = self.conf.get_security_trusted_certificate_directory()
            idp = self.conf.get_security_cilogon_identity_provider()
            dn_prefix = self.conf.get_security_cilogon_dn_prefix()
            ca = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-basic.pem")
            signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-basic.signing_policy")
            cahash = security.get_certificate_hash_from_data(ca)
            security.install_ca(cadir, ca, signing_policy)
            # read from installed conf instead?
            # the | prefix makes it optional, only one callout must succeed
            conf_file.write("|globus_mapping libglobus_gridmap_eppn_callout " +
                    "globus_gridmap_eppn_callout ENV:")
            conf_file.write(
                    "GLOBUS_MYPROXY_CA_CERT=%s " %
                    (os.path.join(cadir, cahash + ".0")))
            conf_file.write(
                    "GLOBUS_MYPROXY_AUTHORIZED_DN=" +
                    "\"%s/O=%s\"\n" % (dn_prefix, idp))
                    
            ca = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-silver.pem")
            signing_policy = pkgutil.get_data(
                    "globus.connect.security",
                    "cilogon-silver.signing_policy")
            cahash = security.get_certificate_hash_from_data(ca)
            security.install_ca(cadir, ca, signing_policy)
            # read from installed conf instead?
            # the | prefix makes it optional, only one callout must succeed
            conf_file.write("|globus_mapping libglobus_gridmap_eppn_callout " +
                    "globus_gridmap_eppn_callout ENV:")
            conf_file.write(
                    "GLOBUS_MYPROXY_CA_CERT=%s " %
                    (os.path.join(cadir, cahash + ".0")))
            conf_file.write(
                    "GLOBUS_MYPROXY_AUTHORIZED_DN=" +
                    "\"%s/O=%s\"\n" % (dn_prefix, idp))

        finally:
            conf_file.close()

        self.logger.debug("EXIT: IO.configure_cilogon()")

    def configure_gridmap(self, conf_file_name, conf_link_name, **kwargs):
        self.logger.debug("ENTER: configure_gridmap()")

        conf_file = file(conf_file_name, "w")
        try:
            conf_file.write("$GRIDMAP \"%s\"\n" %(
                self.conf.get_security_gridmap()))
            os.symlink(conf_file_name, conf_link_name)
        finally:
            conf_file.close()
        self.logger.debug("EXIT: configure_gridmap()")

    def cleanup_logging(self):
        if os.path.lexists(self.logrotate_path):
            os.remove(self.logrotate_path)

    def cleanup(self, **kwargs):
        if not self.is_local():
            return
        
        for name in os.listdir(self.etc_gridftp_d):
            if name.startswith("globus-connect-server") \
                        or name.startswith("globus-connect-multiuser") \
                        or name.startswith("gcmu"):
                os.remove(os.path.join(self.etc_gridftp_d, name))
        self.cleanup_trust_roots()
        self.cleanup_logging()
        self.stop()
        self.disable()
        server = self.conf.get_gridftp_server()
        scheme = "gsiftp"
        port = 2811
        hostname = None

        if "://" in server:
            (scheme, server) = server.split("://", 1)

        if ":" in server:
            (hostname, port_s) = server.split(":", 1)
            port = int(port_s)
        else:
            hostname = server
        server = scheme + "://" + hostname + ":" + str(port)

        if kwargs.get("delete"):
            try:
                self.api.delete_endpoint(self.endpoint_xid)
                if os.path.exists(self.endpoint_id_file):
                    os.remove(self.endpoint_id_file)
            except GlobusAPIError as e:
                if e.http_status != 404:
                    raise e
        else:
            try:
                result = self.api.get_endpoint(self.endpoint_xid)
                data = result.data
            except GlobusAPIError as e:
                if e.http_status != 404:
                    raise e
                data = {'DATA':[]}

            for sdata in data['DATA']:
                if (sdata.get('uri') == gcmu.to_unicode(server)):
                    sid = sdata['id']
                    try:
                        self.api.delete_endpoint_server(
                            self.endpoint_xid, sid)
                    except GlobusAPIError as e:
                        if e.http_status != 404:
                            raise e

    def bind_to_endpoint(self, **kwargs):
        """
        Adds this gridftp server to the endpoint named in the configuration
        file. If force=True is passed, then the endpoint is deleted prior
        to binding this gridftp server. If reset=True is passed, then
        all other GridFTP servers will be removed from this endpoint before
        adding this one.
        """
        self.logger.debug("ENTER: IO.bind_to_endpoint()")

        if self.endpoint_xid is None:
            return

        if kwargs.get('force'):
            try:
                self.logger.debug("Removing old endpoint definition")
                self.api.endpoint_delete(self.endpoint_xid)
                if os.path.exists(self.endpoint_id_file):
                    os.remove(self.endpoint_id_file)
                self.endpoint_xid = urllib_parse.quote(
                    self.conf.get_endpoint_name())
            except:
                pass

        self.logger.debug("Configuring endpoint " + self.endpoint_xid)
        endpoint_public = self.conf.get_endpoint_public()
        endpoint_default_dir = self.conf.get_endpoint_default_dir()

        server = self.conf.get_gridftp_server()
        scheme = "gsiftp"
        port = 2811
        hostname = None

        if "://" in server:
            (scheme, server) = server.split("://", 1)

        if ":" in server:
            (hostname, port_s) = server.split(":", 1)
            port = int(port_s)
        else:
            hostname = server
        server = scheme + "://" + hostname + ":" + str(port)

        oauth_server = None
        myproxy_server = None
        myproxy_dn = None
        if self.conf.get_security_identity_method() == \
                self.conf.IDENTITY_METHOD_OAUTH:
            oauth_server = self.conf.get_oauth_server()
            if oauth_server is None:
                raise Exception("Configured to use OAuth, but no OAuth server defined")
        elif self.conf.get_security_identity_method() == \
                self.conf.IDENTITY_METHOD_CILOGON:
            oauth_server = "cilogon.org"
        else:
            myproxy_server = self.conf.get_myproxy_server()
            myproxy_dn = self.conf.get_myproxy_dn()
            if myproxy_dn is None and myproxy_server is not None:
                myproxy_dn = self.get_myproxy_dn_from_server()

        if myproxy_server is not None:
            myproxy_server = gcmu.to_unicode(myproxy_server)
        if myproxy_dn is not None:
            myproxy_dn = gcmu.to_unicode(myproxy_dn)
        if oauth_server is not None:
            if ":" in oauth_server:
                raise Exception("[OAuth] Server value must be a public host name only")
            oauth_server = gcmu.to_unicode(oauth_server)

        new_gridftp_server = {
                gcmu.to_unicode('DATA_TYPE'): gcmu.to_unicode('server'),
                gcmu.to_unicode('scheme'): gcmu.to_unicode(scheme),
                gcmu.to_unicode('hostname'): gcmu.to_unicode(hostname),
                gcmu.to_unicode('port'): port,
                gcmu.to_unicode('subject'): gcmu.to_unicode(security.get_certificate_subject(self.conf.get_security_certificate_file()))
        }

        try:
            new_endpoint = {
                'DATA_TYPE': 'endpoint'
            }
            result = self.api.get_endpoint(self.endpoint_xid)
            data = result.data
            default_directory_key = 'default_directory'
            public_key = 'public'
            myproxy_server_key = 'myproxy_server'
            myproxy_dn_key = 'myproxy_dn'
            oauth_server_key = 'oauth_server'
            hostname_key = 'hostname'
            id_key = 'id'
            data_key = 'DATA'

            # Update any changed endpoint-level metadata
            if data.get(default_directory_key) != endpoint_default_dir:
                self.logger.debug(
                    "Changing default_directory on endpoint "
                    "to [{}]".format(endpoint_default_dir))
                new_endpoint[default_directory_key] = endpoint_default_dir

            if data.get(public_key) != endpoint_public:
                self.logger.debug("Changing public to " + str(endpoint_public))
                new_endpoint[public_key] = endpoint_public

            if data.get(myproxy_server_key) != myproxy_server:
                self.logger.debug(
                    "Changing myproxy_server to " + str(myproxy_server))
                new_endpoint[myproxy_server_key] = myproxy_server

            if data.get(myproxy_dn_key) != myproxy_dn:
                self.logger.debug("Changing myproxy_dn to " + str(myproxy_dn))
                new_endpoint[myproxy_dn_key] = myproxy_dn

            if data.get(oauth_server_key) != oauth_server:
                self.logger.debug(
                    "Changing oauth_server to " + str(oauth_server))
                new_endpoint[oauth_server_key] = oauth_server

            if len(new_endpoint.keys()) > 1:
                self.logger.debug("Updating endpoint")
                result = self.api.update_endpoint(
                    self.endpoint_xid, new_endpoint)
                self.logger.debug("endpoint update result: {}".format(
                    result.http_status))
                if self.endpoint_xid != result.data['id']:
                    self._update_xid(result.data['id'])

            result = self.api.endpoint_server_list(self.endpoint_xid)
            data = result.data
            self.logger.debug(
                "Existing endpoint server list: "
                + str(data.get(data_key, [])))
            for server_item in data.get(data_key, []):
                self.logger.debug(
                    "existing server for endpoint: "
                    + str(server_item.get(hostname_key, "")))
                this_server_hostname = server_item.get(hostname_key)
                this_server_id = server_item.get(id_key)
                if (kwargs.get('reset')
                        or this_server_hostname == gcmu.to_unicode(hostname)):
                    self.logger.debug(
                        "deleting server entry for "
                        + str(this_server_hostname) + " with id  "
                        + str(this_server_id))
                    self.api.delete_endpoint_server(
                        self.endpoint_xid, this_server_id)
            self.api.add_endpoint_server(
                self.endpoint_xid, new_gridftp_server)
        except GlobusAPIError as e:
            if e.http_status == 404:
                self.logger.debug(
                    "endpoint {} does not exist, creating" .format(
                        self.endpoint_xid))
                try:
                    result = self.api.create_endpoint(dict(
                        canonical_name=self.conf.get_endpoint_name(),
                        default_directory=endpoint_default_dir,
                        public=endpoint_public,
                        is_globus_connect=False,
                        DATA=[dict(
                            DATA_TYPE="server",
                            hostname=new_gridftp_server['hostname'],
                            scheme=new_gridftp_server['scheme'],
                            port=new_gridftp_server['port'],
                            subject=new_gridftp_server['subject'])],
                        myproxy_server=myproxy_server,
                        myproxy_dn=myproxy_dn,
                        oauth_server=oauth_server))
                    if self.endpoint_xid != result.data['id']:
                        self._update_xid(result.data['id'])
                except GlobusAPIError as e:
                    self.logger.error("endpoint create failed: %s" % \
                        (e.message))
                    self.errorcount += 1
            else:
                self.logger.error("endpoint failed: %s" % (e.message))
                self.errorcount += 1
        self.logger.debug("EXIT: IO.bind_to_endpoint()")

    def _update_xid(self, xid):
        with open(self.endpoint_id_file, 'w') as f:
            f.write("{}\n".format(xid))
        self.endpoint_xid = xid

# vim: filetype=python:
