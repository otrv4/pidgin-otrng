%global snapshot 0
Summary: Off-The-Record Messaging plugin for Pidgin
Name: pidgin-otr
Version: 4.0.0
Release: 1%{?dist}
Source: https://otr.cypherpunks.ca/%{name}-%{version}.tar.gz
Url: https://otr.cypherpunks.ca/
License: GPLv2
Group: Applications/Internet
Provides: gaim-otr = %{version}
Obsoletes: gaim-otr < 3.0.1-0.7.20060712cvs
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: pidgin >= 2.0.0, libotr >= 4.0.0
BuildRequires: glib2-devel, gtk2-devel, libgcrypt-devel >= 1.2.0
BuildRequires: libgpg-error-devel, libotr-devel >= 4.0.0
BuildRequires: pidgin-devel >= 2.0.0, perl(XML::Parser), gettext
BuildRequires: intltool
%if %{snapshot}
BuildRequires: libtool automake autoconf
%endif

%description 
This is a Pidgin plugin which implements Off-the-Record (OTR) Messaging.
It is known to work (at least) under the Linux and Windows versions of
Pidgin.

%prep
%setup -q
%if %{snapshot}
aclocal
intltoolize --force --copy
autoreconf -s -i
%endif

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

%files -f %{name}.lang
%doc README COPYING
%{_libdir}/pidgin/pidgin-otr.so

%changelog
* Sat Jul 27 2013 Paul Wouters <pwouters@redhat.com> - 4.0.0-1
- Updated to 4.0.0 - requires libotr >= 4.0.0

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Mon May 14 2012 Paul Wouters <pwouters@redhat.com> - 3.2.1-1
- Updated to 3.2.1. The only change is for CVE-2012-2369

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.2.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Sun Jun 15 2008 Paul Wouters <paul@cypherpunks.ca> 3.2.0-1
- Updated to 3.2.0

* Tue Feb 19 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 3.1.0-3
- Autorebuild for GCC 4.3

* Mon Aug  6 2007 Paul Wouters <paul@cypherpunks.ca> 3.1.0-2
- Fixed Buildrequires
- Versioned the gaim-otr Obsolete:
- Changed license to GPLv2

* Thu Aug  2 2007 Paul Wouters <paul@cypherpunks.ca> 3.1.0-1
- Added locale support to spec file
- Upgraded to current version
- Added Obsoletes for gaim-otr, now that the package is called pidgin-otr

* Fri May 11 2007 Stu Tomlinson <stu@nosnilmot.com> 3.0.1-0.5.20060712cvs
- Actually fix it to work with Pidgin

* Wed Apr 18 2007 Paul Wouters <paul@cypherpunks.ca> 3.0.1-0.4.20060921cvs
- Support for the rename of gaim to pidgin

* Sat Oct 28 2006 Paul Wouters <paul@cypherpunks.ca> 3.0.1-0.3.20060921cvs
- Added patch for gaim 2.0.0-beta4

* Mon Oct  2 2006 Paul Wouters <paul@cypherpunks.ca> 3.0.1-0.2.20060921cvs
- rebuilt for unwind info generation, broken in gcc-4.1.1-21

* Fri Sep 22 2006 Paul Wouters <paul@cypherpunks.ca> 3.0.1-0.1.20060921cvs
- Made an error in the cvs version number, breaking the upgrade path.

* Thu Sep 21 2006 Paul Wouters <paul@cypherpunks.ca> 3.0.0-0.5.20060921cvs
- Bumped to build 5
- gaim-devel package now exists and is needed
- Various fixes to setup section for using versioned 

* Thu Jul 12 2006 Paul Wouters <paul@cypherpunks.ca> 3.0.1-0.1.20060712cvs
- Upgrade to CVS version because no full release of gaim-otr supports
  gaim version 2.x yet, and there is an API change between gaim 1.x and 2.x

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
- install fix for x86_64

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

