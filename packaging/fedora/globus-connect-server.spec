Name:           globus-connect-server
%global         _name %(tr - _ <<< %{name})
Version:        4.0.53
Release:        1%{?dist}
Summary:        Globus Connect Server

%if %{?rhel}%{!?rhel:0} == 6 || %{?rhel}%{!?rhel:0} == 7
%global         __python3           /usr/bin/python3.4
%global         python3_pkgversion  34
%global         py3_build %{expand:\\\
%{__python3} %{py_setup} %{?py_setup_args} build --executable="%{__python3} %{py_shbang_opts}" %{?*}
}
%global         py3_install %{expand:\\\
%{__python3} %{py_setup} %{?py_setup_args} install -O1 --skip-build --root %{buildroot} %{?*}
}
%endif

%global         globus_sdk_name globus_sdk
%global         globus_sdk_version  1.7.1
%global         globus_sdk_wheel %{globus_sdk_name}-%{globus_sdk_version}-py2.py3-none-any.whl
%if %{?rhel}%{!?rhel:0} == 6 || %{?rhel}%{!?rhel:0}  == 7
%global         pyjwt_name PyJWT
%global         pyjwt_version 1.7.1
%global         pyjwt_wheel %{pyjwt_name}-%{pyjwt_version}-py2.py3-none-any.whl
%endif

Group:          System Environment/Libraries
License:        ASL 2.0
URL:            http://www.globus.org/
Source:         %{_name}-%{version}.tar.gz
Source1:        %{globus_sdk_wheel}
%if %{?rhel}%{!?rhel:0} == 6 || %{?rhel}%{!?rhel:0}  == 7
Source2:        %{pyjwt_wheel}
%endif



%if %{?rhel}%{!?rhel:0} == 7
BuildRequires:  python3-rpm-macros
%endif

%if %{?fedora}%{!?fedora:0} >= 28
BuildRequires: python3-devel
%endif

%if %{?suse_version}%{!?suse_version:0} >= 1315
BuildRequires:	python-rpm-macros
%global		python3_pkgversion		3
%endif

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{?suse_version}%{!?suse_version:0} < 1315
BuildArch:      noarch
%endif


%if %{?suse_version}%{!?suse_version:0} >= 1315
BuildRequires:  fdupes
%endif

BuildRequires:  python%{python3_pkgversion}
BuildRequires:  python%{python3_pkgversion}-setuptools
BuildRequires:  python%{python3_pkgversion}-six
BuildRequires:  python%{python3_pkgversion}-requests

Requires:       globus-connect-server-common = %{version}
Requires:       globus-connect-server-io = %{version}
Requires:       globus-connect-server-id = %{version}
Requires:       globus-connect-server-web = %{version}

Requires:  python%{python3_pkgversion}
Requires:  python%{python3_pkgversion}-setuptools
Requires:  python%{python3_pkgversion}-six
Requires:  python%{python3_pkgversion}-requests


%if %{?fedora}%{!?fedora:0} >= 28 ||  %{?rhel}%{!?rhel:0} >= 6
Requires:       crontabs
%endif

%description
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name} package contains:
Globus Connect Server

%package common
Obsoletes:      gcmu
Obsoletes:      globus-connect-multiuser
Obsoletes:      globus-connect-multiuser-common
Obsoletes:      globus-connect-multiuser-io
Obsoletes:      globus-connect-multiuser-id
Obsoletes:      globus-connect-multiuser-web
Summary:        Globus Connect Server Common files
Group:          System Environment/Libraries
%description common
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-common package contains:
Globus Connect Server Common Files

%package id
Requires:       myproxy
Requires:       myproxy-server
Requires:       gsi-openssh
Requires:       gsi-openssh-clients
Requires:       globus-gsi-cert-utils-progs
Requires:       globus-simple-ca
Requires:       globus-connect-server-common = %{version}
Summary:        Globus Connect Server ID for MyProxy configuration
Group:          System Environment/Libraries
%description id
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-id package contains:
Globus Connect Server ID

%package io
Requires:       myproxy
Requires:       gsi-openssh
Requires:       gsi-openssh-clients
Requires:       globus-gsi-cert-utils-progs
Requires:       globus-gridftp-server-progs >= 9.3
Requires:       globus-gass-copy-progs
Requires:       globus-gss-assist-progs
%if %{?suse_version}%{!?suse_version:0} >= 1315
Requires:       libglobus_callout0 >= 2.4
Requires:       libglobus_gridmap_verify_myproxy_callout >= 1.2
Requires:       libglobus_gridmap_eppn_callout >= 0.4
%else
Requires:       globus-callout >= 2.4
Requires:       globus-gridmap-verify-myproxy-callout >= 1.2
Requires:       globus-gridmap-eppn-callout >= 0.4
%endif
Requires:       globus-connect-server-common = %{version}
Summary:        Globus Connect Server I/O for GridFTP configuration
Group:          System Environment/Libraries
%description io
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-io package contains:
Globus Connect Server I/O

%package web
Requires:       myproxy
Requires:       myproxy-oauth
Requires:       globus-connect-server-common = %{version}
Summary:        Globus Connect Server Web for MyProxy OAuth configuration
Group:          System Environment/Libraries
%description web
The Globus Toolkit is an open source software toolkit used for building Grid
systems and applications. It is being developed by the Globus Alliance and
many others all over the world. A growing number of projects and companies are
using the Globus Toolkit to unlock the potential of grids for their cause.

The %{name}-web package contains:
Globus Connect Server Web

%prep
%setup -q -n %{_name}-%{version}

%build
%py3_build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_datadir}/%{name}-common 

PYTHONPATH=$RPM_BUILD_ROOT%{_datadir}/%{name}-common %{__python3} -measy_install -x -N --install-dir $RPM_BUILD_ROOT%{_datadir}/%{name}-common %_sourcedir/%{globus_sdk_wheel}
%if %{?rhel}%{!?rhel:0} == 6 || %{?rhel}%{!?rhel:0}  == 7
PYTHONPATH=$RPM_BUILD_ROOT%{_datadir}/%{name}-common %{__python3} -measy_install -x -N --install-dir $RPM_BUILD_ROOT%{_datadir}/%{name}-common %_sourcedir/%{pyjwt_wheel}
%endif

%py3_install

for script in $RPM_BUILD_ROOT/%{_bindir}/globus*; do
    sed -e '1aimport site\nsite.addsitedir("/usr/share/globus-connect-server-common")\n' -i $script;
done


# Set __python to __python3 to use it for byte-compiling private dependencies 
# in %{_datadir}/%{name}-common in the post-{%}install scriptlet
%global __python %__python3

%if %{?suse_version}%{!?suse_version:0} >= 1315
/usr/lib/rpm/brp-python-bytecompile %{__python3}
%fdupes $RPM_BUILD_ROOT/usr/lib/python%{python3_version}/site-packages/globus
%fdupes $RPM_BUILD_ROOT%{_datadir}/%{name}-common
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/globus-connect-server-setup
%{_bindir}/globus-connect-server-cleanup
%{_mandir}/man8/globus-connect-server-setup*
%{_mandir}/man8/globus-connect-server-cleanup*
%files common
%defattr(-,root,root,-)
%{_datadir}/globus-connect-server-common/*
/usr/lib*/python*
%dir %{_datadir}/globus-connect-server-common

%config(noreplace) %{_sysconfdir}/%{name}.conf
%files id
%defattr(-,root,root,-)
%{_bindir}/globus-connect-server-id-setup
%{_bindir}/globus-connect-server-id-cleanup
%{_mandir}/man8/globus-connect-server-id-*
%files io
%defattr(-,root,root,-)
%{_bindir}/globus-connect-server-io-setup
%{_bindir}/globus-connect-server-io-cleanup
%{_mandir}/man8/globus-connect-server-io-*
%files web
%defattr(-,root,root,-)
%{_bindir}/globus-connect-server-web-setup
%{_bindir}/globus-connect-server-web-cleanup
%{_mandir}/man8/globus-connect-server-web-*

%changelog
* Fri May 10 2019 Globus Toolkit <support@globus.org> 4.0.53-1
- Update to new Globus SDK, repackage using python3

* Thu Jan 10 2019 Globus Toolkit <support@globus.org> 4.0.51-2
- Add missing dependency on crontabs for RHEL-based systems

* Mon Dec 03 2018 Globus Toolkit <support@globus.org> 4.0.51-1
- Fix for CILogon IdPs that do not support full R&S attributes

* Tue Nov 20 2018 Globus Toolkit <support@globus.org> 4.0.50-1
- Support non-InCommon CILogon IdPs
- Update CILogon IdP list

* Mon May 7 2018 Globus Toolkit <support@globus.org> 4.0.49-1
- Add retries to http downloads for version and ec2 checking.
- Fix ec2 checks not failing in Azure.

* Mon Apr 9 2018 Globus Toolkit <support@globus.org> 4.0.48-1
- Update CILogon IdP list

* Tue Dec 12 2017 Globus Toolkit <support@globus.org> 4.0.46-1
- Fix DN parsing for openssl 1.1.x

* Thu May 04 2017 Globus Toolkit <support@globus.org> 4.0.45-1
- Change MyProxy CA cert naming convention to allow easier establishment
  of trust between io and id nodes
- Update Globus Connect CA name in myproxy ca dn detection code

* Wed Nov 09 2016 Globus Toolkit <support@globus.org> 4.0.43-1
- Fix upgrade workaround message

* Mon Nov 07 2016 Globus Toolkit <support@globus.org> 4.0.42-1
- Set Transfer API Client timeout

* Tue Sep 20 2016 Globus Toolkit <support@globus.org> 4.0.41-1
- Update SUSE vhost configuration
- Fix get() got an unexpected keyword argument 'raw'

* Mon Sep 12 2016 Globus Toolkit <support@globus.org> 4.0.39-1
- Merge pull #5 (Add missingok to logrotate)

* Mon Sep 12 2016 Globus Toolkit <support@globus.org> 4.0.38-1
- Fix RHEL 7.2 platform name matching

* Thu Sep  1 2016 Globus Toolkit <support@globus.org> 4.0.37-3
- Update dependencies for SLES 12

* Tue Aug 30 2016 Globus Toolkit <support@globus.org> 4.0.37-1
- Don't change From "Globus Id" to "Globus Username" in prompt

* Thu May 26 2016 Globus Toolkit <support@globus.org> 4.0.36-1
- Fix IdP verification on older versions of python

* Mon May 16 2016 Globus Toolkit <support@globus.org> 4.0.35-1
- Fix IdP list download

* Mon May 16 2016 Globus Toolkit <support@globus.org> 4.0.34-1
- Add OS/Arch to usage stats

* Thu May 12 2016 Globus Toolkit <support@globus.org> 4.0.33-1
- Verify CILogon IdP against automatically updated list

* Tue May 10 2016 Globus Toolkit <support@globus.org> 4.0.32-1
- Don't attempt to fetch myproxy keys when it isn't configured.
- Soften required upgrade message

* Mon May 02 2016 Globus Toolkit <support@globus.org> 4.0.31-1
- Detect if the new go-ca3 is missing, and if so request a new cert when
  doing setup

* Thu Apr 28 2016 Globus Toolkit <support@globus.org> 4.0.29-1
- Change method for acquiring host certificates
- Replace expiring Globus Connect CA
- Change user prompt to Globus ID:
- strip @globusid.org if present in username

* Mon Mar 28 2016 Globus Toolkit <support@globus.org> 4.0.28-1
- Add Princeton University to CILogon IdP list

* Mon Dec 14 2015 Globus Toolkit <support@globus.org> 4.0.27-1
- Relocate imports to allow --help to work

* Mon Nov 30 2015 Globus Toolkit <support@globus.org> 4.0.26-1
- Catch exceptions when attempting to check version file

* Mon Nov 23 2015 Globus Toolkit <support@globus.org> 4.0.25-1
- Add RequireEncryption GridFTP configuration 

* Mon Nov 16 2015 Globus Toolkit <support@globus.org> 4.0.24-1
- Add UNC-Charlotte to CILogon regex

* Fri Sep 4 2015 Globus Toolkit <support@globus.org> 4.0.23-1
- Use retries in transferapi instead of forcing our own

* Wed Sep 2 2015 Globus Toolkit <support@globus.org> 4.0.22-1
- Upgrade to transferapi version 0.10.16
- Replace obsolescent endpoint_update calls
- Changes for python3 compatibility
- Add is-this-the-latest-version? check

* Mon Jun 01 2015 Globus Toolkit <support@globus.org> 4.0.18-1
- Fix typo

* Thu May 28 2015 Globus Toolkit <support@globus.org> 4.0.17-1
- Add html version of documentation to source
- Note managed endpoint configuration needed when enabling sharing

* Tue Apr 28 2015 Globus Toolkit <support@globus.org> 4.0.16-1
- Use systemctl where available

* Tue Mar 3 2015 Globus Toolkit <support@globus.org> 4.0.15-1
- Bump GridFTP requirement

* Tue Mar 3 2015 Globus Toolkit <support@globus.org> 4.0.14-1
- Add Groups/Users Allow/Deny options for GridFTP sharing

* Tue Mar 3 2015 Globus Toolkit <support@globus.org> 4.0.13-1
- Add gridftp logging

* Fri Nov 14 2014 Globus Toolkit <support@globus.org> 4.0.11-1
- New anoncert/anonkey

* Fri Nov 07 2014 Globus Toolkit <support@globus.org> 4.0.10-1
- Fix some config file validitation errors with valid values

* Fri Nov 07 2014 Globus Toolkit <support@globus.org> 4.0.9-1
- Fix enabling of apache2 modules

* Tue Oct 28 2014 Globus Toolkit <support@globus.org> 4.0.8-1
- GT-569: globus-connect-server doesn't catch some configuration errors

* Wed Sep 10 2014 Globus Toolkit <support@globus.org> 4.0.7-1
- Update version after commit was done without version change

* Mon Aug 04 2014 Globus Toolkit <support@globus.org> 4.0.6-1
- Fix incorrect SuSE paths

* Fri Aug 01 2014 Globus Toolkit <support@globus.org> 4.0.5-1
- Compatibility with Ubuntu 14.04

* Thu Jul 31 2014 Globus Toolkit <support@globus.org> 4.0.4-1
- Compatibility with SLES 11.3

* Tue Jul 29 2014 Globus Toolkit <support@globus.org> 4.0.3-1
- Compatibility with CentOS 7

* Mon Jun 23 2014 Globus Toolkit <support@globus.org> 4.0.2-1
- Improve diagnostics when IdentityMethod = OAuth and [OAuth] section doesn't
  contain a server name

* Thu Jun 05 2014 Globus Toolkit <support@globus.org> 4.0.1-1
- GT-537: GCS uses multiuser in config settings and doc

* Thu May 29 2014 Globus Toolkit <support@globus.org> 4.0.0-1
- Prep for GT6

* Thu Oct 24 2013 Globus Toolkit <support@globus.org> 3.0.0-1
- Bump to new version

* Mon Oct 07 2013 Globus Toolkit <support@globus.org> 2.0.61-1
- Rename from globus-connect-multiuser to globus-connect-server

* Tue Sep 10 2013 Globus Toolkit <support@globus.org> 2.0.60-1
- KOA-2743: CILogin Reference in globus-connect-multiuser.conf is incorrect

* Tue Sep 10 2013 Globus Toolkit <support@globus.org> 2.0.59-1
- GT-439: globus-connect-multiuser-setup has no output on successful setup

* Thu Aug 22 2013 Globus Toolkit <support@globus.org> 2.0.58-1
- Disable OAuth by default, use MyProxy, instead of having OAuth enabled but
  not used.

* Thu Aug 15 2013 Globus Toolkit <support@globus.org> 2.0.57-1
- GT-433: Add option to enable UDT

* Tue Jul 23 2013 Globus Toolkit <support@globus.org> 2.0.56-1
- KOA-2698: GCMU Setup Throws TypeError when checking for timeouts
- KOA-2701: GCMU defaults to MyProxy, not OAuth

* Fri Jun 14 2013 Globus Toolkit <support@globus.org> 2.0.55-1
- GCMU doesn't handle hashes from remote myproxy with different openssl version

* Fri Jun 07 2013 Globus Toolkit <support@globus.org> 2.0.54-1
- KOA-2632: gcmu doesn't set myproxy_dn unless it is in config file

* Thu Jun 06 2013 Globus Toolkit <support@globus.org> 2.0.53-1
- set default umask

* Thu Jun 06 2013 Globus Toolkit <support@globus.org> 2.0.52-1
- CILogon fix

* Thu Jun 06 2013 Globus Toolkit <support@globus.org> 2.0.51-1
- Use new chaining support in globus-callout to enable both CILogon CAs
- Set a version_tag for GridFTP

* Tue Jun 04 2013 Globus Toolkit <support@globus.org> 2.0.50-1
- Update to 2.0.50
- Quiet some of the output from external commands when they succeed

* Mon Jun 03 2013 Globus Toolkit <support@globus.org> 2.0.49-1
- Update to 2.0.49
- Allow override of GO instance to use to via environment

* Thu May 30 2013 Globus Toolkit <support@globus.org> 2.0.48-1
- Update to 2.0.48
- Fix args to endpoint_create()

* Thu May 30 2013 Globus Toolkit <support@globus.org> 2.0.47-1
- Update to 2.0.47
- Fix args to api.endpoint() in create wrapper

* Thu May 30 2013 Globus Toolkit <support@globus.org> 2.0.46-1
- Update to 2.0.46
- Check for existing endpoint if endpoint_create times out and then
  we get a 409 Conflict response

* Thu May 30 2013 Globus Toolkit <support@globus.org> 2.0.45-1
- Update to 2.0.45
- Fix logic inversion
- Filter nonprintable strings from output

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.44-1
- Update to 2.0.44
- Increase delay between timeout retries

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.43-1
- Update to 2.0.43
- fix typo related to previous

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.42-1
- Update to 2.0.42
- wrap api.endpoint with retries

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.41-1
- Update to 2.0.41
- KOA-2604 related problem 

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.40-1
- Update to 2.0.40
- Fix retry wrapper return value

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.39-1
- Update to 2.0.39
- Different approach to KOA-2601: occasional endpoint create/update timeouts

* Wed May 29 2013 Globus Toolkit <support@globus.org> 2.0.38-1
- Update to 2.0.38
- KOA-2602: globus-connect-multiuser-cleanup doesn't clean up myproxy server
- KOA-2603: globus-connect-multiuser-* commands don't error when -c
            CONFIGFILE doesn't exist
- KOA-2604: globus-connect-multiuser-cleanup exits with exception if the
            endpoint doesn't exist
- KOA-2605: GCMU endpoint default dir doesn't seem to be set correctly in GO
- KOA-2608: gcmu scripts are very chatty
- KOA-2601: occasional endpoint create/update timeouts
- KOA-2613: globus-connect-multiuser-id-cleanup tries to clean up myproxy
            even if it's not configured

* Fri May 24 2013 Globus Toolkit <support@globus.org> 2.0.37-1
- KOA-2607: GCMU fetches wrong format CRL file

* Mon May 20 2013 Globus Toolkit <support@globus.org> 2.0.36-3
- update dep versions

* Mon May 20 2013 Globus Toolkit <support@globus.org> 2.0.36-1
- fix for io-setup when oath = None

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.35-1
- non-zero exit when setup or cleanup fails
- trap keyboard interrupts and exit more quietly

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.34-1
- Fix replacing server uri on the same host without -s
- Fix runtime error when removing a server from an endpoint

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.33-1
- Update to 2.0.33. New sharing DN

* Fri May 17 2013 Globus Toolkit <support@globus.org> 2.0.32-1
- Update to 2.0.32. Assume non-resolvable name is local

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.31-1
- Fix -s option to reset endpoint gridftp server

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.30-1
- Ignore myproxy CA cleanup if cacert.pem doesn't exist

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.29-1
- Ignore myproxy CA cleanup if using cilogon

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.28-1
- Update to 2.0.28
- KOA-2583: Add CILogon Silver CA to set of trusted CAs in GCMU
- KOA-2584: Add Globus Online Transfer CA 2 Alpha only if sharing is enabled on GCMU

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.27-2
- use new transfer api client

* Thu May 16 2013 Globus Toolkit <support@globus.org> 2.0.27-1
- Add conditional enable of mod_wsgi

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.26-2
- Require same version of other subpackages

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.26-1
- Update to 2.0.26. Fix scoping problem, don't create sharing dir if None

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.25-1
- Update to 2.0.25. Avoid trying to configure non-local services

* Wed May 15 2013 Globus Toolkit <support@globus.org> 2.0.24-1
- Update to 2.0.24. Fixes to MANIFEST.in

* Tue May 14 2013 Globus Toolkit <support@globus.org> 2.0.23-1
- Update to 2.0.23. Fixes to sharing-related config

* Mon May 13 2013 Globus Toolkit <support@globus.org> 2.0.22-1
- Update to 2.0.22. Fix path to version file.

* Thu May 09 2013 Globus Toolkit <support@globus.org> 2.0.21-1
- Update to 2.0.21. Remove some config options.

* Wed May 08 2013 Globus Toolkit <support@globus.org> 2.0.20-1
- Update to 2.0.20

* Wed May 08 2013 Globus Toolkit <support@globus.org> 2.0.19-1
- Update to 2.0.19

* Fri Apr 26 2013 Globus Toolkit <support@globus.org> 2.0.17-1
- Remove outdated sharing options SharingFile and SharingFileControl

* Wed Apr 10 2013 Globus Toolkit <support@globus.org> 2.0.16-1
- Change from SharingFile to SharingStateDir

* Mon Mar 25 2013 Globus Toolkit <support@globus.org> 2.0.15-1
- Add options to remove and reset an endpoint

* Fri Mar 22 2013 Globus Toolkit <support@globus.org> 2.0.14-2
- Require some minimum package versions

* Fri Mar 22 2013 Globus Toolkit <support@globus.org> 2.0.14-1
- Enable the gridftp and myproxy services to run at boot time
- Add globus-connect-multiuser version number to the gridftp server's usage
  stats data

* Thu Mar 21 2013 Globus Toolkit <support@globus.org> 2.0.13-1
- Fix configuring services with non-default port

* Thu Mar 21 2013 Globus Toolkit <support@globus.org> 2.0.12-1
- Add detection of ec2 private IP addresses and set DataInterface
- Better automatic support of NATed servers
- Don't depend on particular arch for GT components

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.11-1
- Missing break in retry code

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.10-1
- Add retries on getting authentication token

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.9-1
- Fix some configuration file handling

* Tue Mar 19 2013 Globus Toolkit <support@globus.org> 2.0.8-1
- Fix some configuration file handling
- Fix nameopt for ca creation for real
- add socket timeout

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> 2.0.7-1
- remove @PYTHON@ from globus-connect-multiuser-setup
- Fix nameopt for ca creation

* Mon Mar 18 2013 Globus Toolkit <support@globus.org> 2.0.6-2
- Update transfer api client version

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.6-1
- fix issues where MyProxyCA DN doesn't match MyProxy DN

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.5-1
- Fix setup.py

* Fri Mar 15 2013 Globus Toolkit <support@globus.org> 2.0.4-1
- fix MANIFEST.in

* Thu Mar 14 2013 Globus Toolkit <support@globus.org> 2.0.3-1
- dummy __init__.py

* Wed Mar 13 2013 Globus Toolkit <support@globus.org> 2.0.2-1
- Initial packaging as globus-connect-multiuser
