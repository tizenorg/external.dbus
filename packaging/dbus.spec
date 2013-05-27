Name:		dbus
Summary:	D-Bus message bus
Version:	1.6.4
Release:	5
Group:		System/Libraries
License:	GPLv2+ or AFL
URL:		http://www.freedesktop.org/software/dbus/
Source0:	http://dbus.freedesktop.org/releases/%{name}/%{name}-%{version}.tar.gz
Source1:	dbus-daemon_run
Source2:	dbus-user.socket
Source3:	dbus-user.service
Source4:	system.conf
Source1001:	dbus.manifest
Patch1:         0001-Enable-checking-of-smack-context-from-DBus-interface.patch
Patch2:         0002-Enforce-smack-policy-from-conf-file.patch
Patch3:         0003-dbus_service_highest_prio_setting.patch
Patch4:         slp-relax-permissions.patch
Patch5:         slp-add-services-directory.patch
Patch6:         0006-build-Make-disable-xml-docs-build-work-again.patch
Patch7:         0007-Set-correct-address-when-using-address-systemd.patch
Patch8:         0008-Fix-dbus-daemon-will-crash-due-to-message-rejection.patch
Requires:	%{name}-libs = %{version}
BuildRequires:  expat-devel >= 1.95.5
BuildRequires:  libtool
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(libsmack)
#BuildRequires:  pkgconfig(libsystemd-daemon)
#BuildRequires:  pkgconfig(libsystemd-login)


%description
D-Bus is a system for sending messages between applications. It is used both
for the systemwide message bus service, and as a per-user-login-session
messaging facility.


%package libs
Summary:    Libraries for accessing D-Bus
Group:      System/Libraries
#FIXME: This is circular dependency
Requires:   %{name} = %{version}-%{release}

%description libs
Lowlevel libraries for accessing D-Bus.

%package devel
Summary:    Libraries and headers for D-Bus
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   pkgconfig

%description devel
Headers and static libraries for D-Bus.

%prep
%setup -q -n %{name}-%{version}
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1

%build
cp %{SOURCE1001} .
#CFLAGS="$CFLAGS -DUSE_MONOTONIC"
#LDFLAGS="$LDFLAGS -lrt"

%reconfigure --disable-static \
    --exec-prefix=/ \
    --bindir=%{_bindir} \
    --libexecdir=%{_libdir}/dbus-1 \
    --sysconfdir=%{_sysconfdir} \
    --libdir=%{_libdir} \
    --disable-asserts \
    --disable-xml-docs \
    --disable-selinux \
    --disable-libaudit \
    --enable-tests=no \
    --with-system-pid-file=%{_localstatedir}/run/messagebus.pid \
    --with-dbus-user=root \
    --with-systemdsystemunitdir=%{_libdir}/systemd/system \
    --enable-smack \

make %{?jobs:-j%jobs}

%install
%make_install
%remove_docs

mv %{buildroot}/etc/dbus-1/system.conf %{buildroot}/etc/dbus-1/system.conf.systemd
install -m644 %{SOURCE4} %{buildroot}/etc/dbus-1/system.conf

mkdir -p %{buildroot}%{_libdir}/pkgconfig
# Change the arch-deps.h include directory to /usr/lib instead of /lib
sed -e 's@-I${libdir}@-I${prefix}/%{_lib}@' %{buildroot}%{_libdir}/pkgconfig/dbus-1.pc

mkdir -p %{buildroot}%{_datadir}/dbus-1/interfaces

ln -s dbus.service %{buildroot}%{_libdir}/systemd/system/messagebus.service

mkdir -p %{buildroot}%{_libdir}/systemd/user
install -m0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/user/dbus.socket
install -m0644 %{SOURCE3} %{buildroot}%{_libdir}/systemd/user/dbus.service

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc{3,4}.d
install -m0755 %{SOURCE1} %{buildroot}%{_sysconfdir}/rc.d/init.d/dbus-daemon_run
ln -s ../init.d/dbus-daemon_run %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S02dbus-daemon_run
ln -s ../init.d/dbus-daemon_run %{buildroot}%{_sysconfdir}/rc.d/rc4.d/S02dbus-daemon_run

mkdir -p $RPM_BUILD_ROOT%{_datadir}/license
for keyword in LICENSE COPYING COPYRIGHT;
do
	for file in `find %{_builddir} -name $keyword`;
	do
		cat $file >> $RPM_BUILD_ROOT%{_datadir}/license/%{name};
		echo "";
	done;
done

%post
mkdir -p /opt/var/lib/dbus

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%manifest dbus.manifest
%{_datadir}/license/%{name}
%{_sysconfdir}/rc.d/init.d/*
%{_sysconfdir}/rc.d/rc?.d/*
%{_bindir}/dbus-cleanup-sockets
%{_bindir}/dbus-daemon
%{_bindir}/dbus-monitor
%{_bindir}/dbus-send
%{_bindir}/dbus-uuidgen
%{_bindir}/dbus-launch
%dir %{_sysconfdir}/dbus-1
%config(noreplace) %{_sysconfdir}/dbus-1/session.conf
%dir %{_sysconfdir}/dbus-1/session.d
%config(noreplace) %{_sysconfdir}/dbus-1/system.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.conf.systemd
%dir %{_sysconfdir}/dbus-1/system.d
%dir %{_libdir}/dbus-1
%attr(4750,root,dbus) %{_libdir}/dbus-1/dbus-daemon-launch-helper
%{_libdir}/systemd/system/*
%{_libdir}/systemd/user/*
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/interfaces
%{_datadir}/dbus-1/services
%{_datadir}/dbus-1/system-services
%dir %{_localstatedir}/run/dbus
%dir %{_localstatedir}/lib/dbus

%files libs
%{_libdir}/libdbus-1.so.3*

%files devel
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc
