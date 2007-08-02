Summary: Off-The-Record Messaging plugin for pidgin
Name: pidgin-otr
Version: 3.1.0
Release: 1%{?dist}
Source: http://otr.cypherpunks.ca/%{name}-%{version}.tar.gz
Url: http://otr.cypherpunks.ca/
License: GPL
Group: Applications/Internet
Provides: gaim-otr = %{version}
Obsoletes: gaim-otr
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: pidgin >= 2.0.0, libotr >= 3.1.0
BuildRequires: glib2-devel, gtk2-devel, libgcrypt-devel >= 1.2.0, libgpg-error-devel, pidgin-devel >= 2.0.0, libotr-devel >= 3.1.0, libpurple-devel 

%description 

This is a pidgin plugin which implements Off-the-Record (OTR) Messaging.
It is known to work (at least) under the Linux and Windows versions of
pidgin (2.x).

%prep
%setup -q

%build

%configure 
make %{?_smp_mflags} all


%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
# libtool insists on creating this
rm $RPM_BUILD_ROOT/%{_libdir}/pidgin/pidgin-otr.la
# locale
%find_lang %{name}

%clean
rm -rf $RPM_BUILD_ROOT

%files -f %{name}.lang
%defattr(-, root, root, 0755)
%doc README COPYING
%{_libdir}/pidgin/pidgin-otr.so

%changelog
* Thu Jul 26 2007 Paul Wouters <paul@cypherpunks.ca> 3.1.0-preview2
- Added locale support to spec file
- Upgraded to current version
- Added Obsoletes for gaim-otr, now that the package is called pidgin-otr

* Mon Oct 17 2005 Paul Wouters <paul@cypherpunks.ca> 3.0.0
- Minor change to allow for new documentation files. Ensure
  dependancy on at least libotr version 3.0.0

* Fri Jun 17 2005 Tom "spot" Callaway <tcallawa@redhat.com>
- reworked for Fedora Extras

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

