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

"""Remove a GridFTP server configuration and remove it from a Globus endpoint

globus-connect-server-io-cleanup [-h|--help]
globus-connect-server-io-cleanup {-c FILENAME|--config-file=FILENAME}
                                    {-v|--verbose}
                                    {-r PATH|--root=PATH}
                                    {-d|--delete-endpoint}

The globus-connect-server-io-cleanup command deletes GridFTP service
configuration previously created by running globus-connect-server-io-setup
and removes it from a Globus endpoint. It deletes configuration files,
stops, and disables the GridFTP server. It also removes the server from an
endpoint, optionally deleting the endpoint.

If the -d or --delete-endpoint command-line option is used,
globus-connect-server-io-cleanup removes the endpoint named in the
configuration file as well as cleaning up
globus-connect-server-io-setup-generated configuration files.

If the -r PATH or --root=PATH command-line option is used,
globus-connect-server-io-cleanup will write its GridFTP configuration and
certificates in a subdirectory rooted at PATH instead of /. This means, for
example, that globus-connect-server-io-cleanup deletes GridFTP configuration
files in PATH/etc/gridftp.d.

The following options are available:

-h, --help
                                Display help information
-c FILENAME, --config-file=FILENAME
                                Use configuration file FILENAME instead of
                                /etc/globus-connect-server.conf
-v, --verbose                   Print more information about tasks
-r PATH, --root=PATH            Add PATH as the directory prefix for the
                                configuration files that
                                globus-connect-server-io-cleanup writes
-d, --delete-endpoint           Delete the Globus endpoint
"""

from __future__ import print_function, absolute_import

short_usage = """globus-connect-server-io-cleanup [-h|--help]
globus-connect-server-io-cleanup {-c FILENAME|--config-file=FILENAME}
                                    {-v|--verbose}
                                    {-r PATH|--root=PATH}
                                    {-d|--delete-endpoint}
"""

import getopt
import os
import sys
import traceback

from globus.connect.server import get_api, is_latest_version
from globus.connect.server.io import IO
from globus.connect.server.configfile import ConfigFile

def usage(short=False, outstream=sys.stdout):
    if short:
        print(short_usage, file=outstream)
    else:
        print(__doc__, file=outstream)

def main():
    try:
        conf_filename = None
        api = None
        force = False
        debug = False
        root = "/"
        delete = False
        try:
            opts, arg = getopt.getopt(sys.argv[1:], "hc:vr:df",
                    ["help", "config-file=", "verbose", "root=",
                     "delete-endpoint", "force"])
        except getopt.GetoptError as e:
            print("Invalid option " + e.opt, file=sys.stderr)
            usage(short=True, outstream=sys.stderr)
            sys.exit(1)

        if len(arg) > 0:
            print("Unexpected argument(s) " + " ".join(arg), file=sys.stderr)
            sys.exit(1)
        
        for (o, val) in opts:
            if o in ['-h', '--help']:
                usage()
                sys.exit(0)
            elif o in ['-c', '--config-file']:
                conf_filename = val
            elif o in ['-v',  '--verbose']:
                debug = True
            elif o in ['-r', '--root']:
                root = val
            elif o in ['-d', '--delete-endpoint']:
                delete = True
            elif o in ['-f', '--force']:
                force = True
            else:
                print("Unknown option %s" %(o), file=sys.stderr)
                sys.exit(1)

        is_latest_version(force)

        os.umask(0o22)
        conf = ConfigFile(config_file=conf_filename, root=root)
        api = get_api(conf)
        ioobj = IO(config_obj=conf, api=api, debug=debug)
        ioobj.cleanup(delete=delete)
    except KeyboardInterrupt as e:
        print("Aborting...")
        sys.exit(1)
    except Exception as e:
        if debug:
            traceback.print_exc(file=sys.stderr)
        else:
            print(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
