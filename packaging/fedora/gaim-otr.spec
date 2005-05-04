Summary: Off-The-Record Messaging plugin for GAIM
Name: gaim-otr
%define majver 2
%define minver 0.2
Version: %{majver}.%{minver}
%define debug_package %{nil}
%define ourrelease 1
Release: %{ourrelease}
Source: http://www.cypherpunks.ca/otr/gaim-otr-%{majver}.%{minver}.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
Url: http://www.cypherpunks.ca/otr/
Vendor: Nikita Borisov and Ian Goldberg <otr@cypherpunks.ca>
Packager: Paul Wouters <paul@cypherpunks.ca>
License: GPL
Group: Applications/Internet
Provides: gaim-otr
Obsoletes: otr-plugin
BuildRequires: glib2-devel, gtk2-devel, libgcrypt-devel >= 1.2.0, libgpg-error-devel, gaim >= 1.0.0, libotr-devel >= 2.0.2
Requires: gaim >= 1.0.0, libgcrypt >= 1.2.0, gtk2 >= 2.4, libotr >= 2.0.2
%define __spec_install_post /usr/lib/rpm/brp-compress || :

%description 

This is a gaim plugin which implements Off-the-Record (OTR) Messaging.
It is known to work (at least) under the Linux and Windows versions of
gaim (1.x).

OTR allows you to have private conversations over IM by providing:
 - Encryption
   - No one else can read your instant messages.
 - Authentication
   - You are assured the correspondent is who you think it is.
 - Deniability
   - The messages you send do _not_ have digital signatures that are
     checkable by a third party.  Anyone can forge messages after a
     conversation to make them look like they came from you.  However,
     _during_ a conversation, your correspondent is assured the messages
     he sees are authentic and unmodified.
 - Perfect forward secrecy
   - If you lose control of your private keys, no previous conversation
     is compromised.

For more information on Off-the-Record Messaging, see
http://www.cypherpunks.ca/otr/

%prep
%setup -q -n gaim-otr-%{majver}.%{minver}

%build
%configure --prefix=%{_prefix} --libdir=%{_libdir} --mandir=%{_mandir}
%{__make} \
	CFLAGS="${RPM_OPT_FLAGS}" \
	all

%install
rm -rf ${RPM_BUILD_ROOT}
%{__make} \
	DESTDIR=${RPM_BUILD_ROOT} \
	install
# libtool insists on creating this
rm ${RPM_BUILD_ROOT}/%{_libdir}/gaim/gaim-otr.la

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/gaim/gaim-otr.so
%doc README COPYING 

%changelog
* Tue May  3 2005 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 2.0.2.
* Wed Feb 23 2005 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 2.0.1.
* Tue Feb  8 2005 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 2.0.0.
* Wed Feb  2 2005 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 1.99.0.
* Wed Jan 19 2005 Paul Wouters <paul@cypherpunks.ca>
- Split spec file from libotr and added dependancies
* Tue Dec 21 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 1.0.2.
* Fri Dec 17 2004 Paul Wouters <paul@cypherpunks.ca>
- instll fix for x86_64
* Sun Dec 12 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 1.0.0.
* Fri Dec 10 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.9rc2. 
* Thu Dec  9 2004 Ian Goldberg <otr@cypherpunks.ca>
- Added CFLAGS to "make all", removed DESTDIR
* Wed Dec  8 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.9rc1. 
* Fri Dec  3 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.1. 
* Wed Dec  1 2004 Paul Wouters <paul@cypherpunks.ca>
- Bumped to version 0.9.0. 
- Fixed install for tools and cos
- Added Obsoletes: target for otr-plugin so rpm-Uhv gaim-otr removes it.
* Mon Nov 22 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped version to 0.8.1
* Sun Nov 21 2004 Paul Wouters <paul@cypherpunks.ca>
- Initial version

