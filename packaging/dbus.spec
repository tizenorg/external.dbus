Name:		dbus
Summary:	D-Bus message bus
Version:	1.6.4
Release:	4
Group:		System/Libraries
License:	GPL-2.0+ or AFL-2.1
URL:		http://www.freedesktop.org/software/dbus/
Source0:	http://dbus.freedesktop.org/releases/%{name}/%{name}-%{version}.tar.gz
Source1:	dbus-daemon_run
Source2:	dbus-user.socket
Source3:	dbus-user.service
Source4:	system.conf
Source1001:	dbus.manifest
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

mkdir -p $RPM_BUILD_ROOT%{_datadir}/license
cat COPYING > $RPM_BUILD_ROOT%{_datadir}/license/dbus
cat COPYING > $RPM_BUILD_ROOT%{_datadir}/license/dbus-libs

%post
mkdir -p /var/lib/dbus
ln -sf %{_sysconfdir}/machine-id /var/lib/dbus/machine-id

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_datadir}/license/dbus
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
%manifest dbus.manifest

%files libs
%defattr(-,root,root,-)
%{_datadir}/license/dbus-libs
%{_libdir}/libdbus-1.so.3*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc
