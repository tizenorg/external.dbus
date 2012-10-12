Name:		dbus
Summary:	D-Bus message bus
Version:	1.6.4
Release:	4
Group:		System/Libraries
License:	GPLv2+ or AFL
URL:		http://www.freedesktop.org/software/dbus/
Source0:	http://dbus.freedesktop.org/releases/%{name}/%{name}-%{version}.tar.gz
Source1:	dbus-daemon_run
Source2:	system.conf
Source1001:	dbus.manifest
Requires:	%{name}-libs = %{version}
BuildRequires:  expat-devel >= 1.95.5
BuildRequires:  libtool
BuildRequires:  libx11-devel


%description
D-Bus is a system for sending messages between applications. It is used both
for the systemwide message bus service, and as a per-user-login-session
messaging facility.


%package libs
Summary:    Libraries for accessing D-Bus
Group:      System/Libraries
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

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

%build
cp %{SOURCE1001} .
CFLAGS="$CFLAGS -DUSE_MONOTONIC"
LDFLAGS="$LDFLAGS -lrt"

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

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%remove_docs

mkdir -p %{buildroot}/etc/rc.d/init.d
mkdir -p %{buildroot}/etc/rc.d/rc{3,4}.d
mkdir -p %{buildroot}/usr/etc/dbus-1
cp %{SOURCE1} %{buildroot}/etc/rc.d/init.d/dbus-daemon_run
cp %{SOURCE2} %{buildroot}/etc/dbus-1/system.conf
chmod 755 %{buildroot}/etc/rc.d/init.d/dbus-daemon_run
ln -s ../init.d/dbus-daemon_run  %{buildroot}/etc/rc.d/rc3.d/S04dbus-daemon_run
ln -s ../init.d/dbus-daemon_run %{buildroot}/etc/rc.d/rc4.d/S04dbus-daemon_run

mkdir -p %{buildroot}%{_datadir}/dbus-1/interfaces

ln -s dbus.service %{buildroot}%{_libdir}/systemd/system/messagebus.service

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


%post libs
/sbin/ldconfig


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
%dir %{_sysconfdir}/dbus-1/system.d
%dir %{_libdir}/dbus-1
%attr(4750,root,dbus) %{_libdir}/dbus-1/dbus-daemon-launch-helper
%{_libdir}/systemd/system/dbus.service
%{_libdir}/systemd/system/dbus.socket
%{_libdir}/systemd/system/dbus.target.wants/dbus.socket
%{_libdir}/systemd/system/messagebus.service
%{_libdir}/systemd/system/multi-user.target.wants/dbus.service
%{_libdir}/systemd/system/sockets.target.wants/dbus.socket
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/services
%{_datadir}/dbus-1/system-services
%{_datadir}/dbus-1/interfaces
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
