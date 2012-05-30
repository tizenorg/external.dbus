Name:       dbus
Summary:    D-Bus message bus
Version:    1.4.8
Release:    1
Group:      System/Libraries
License:    GPLv2+ or AFL
URL:        http://www.freedesktop.org/software/dbus/
Source0:    http://dbus.freedesktop.org/releases/%{name}/%{name}-%{version}.tar.gz
Source1:    dbus-daemon_run
Source2:    system.conf
Source1001: packaging/dbus.manifest 
Requires:   %{name}-libs = %{version}
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
Requires:   %{name} = %{version}-%{release}
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

%reconfigure  \
    --disable-xml-docs \
    --enable-tests=no \
    --with-session-socket-dir=/tmp \
    --with-system-socket=/var/run/dbus/system_bus_socket \
    --with-dbus-user=root \
    --with-system-pid-file=/tmp/run/dbus/pid

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
rm -rf $RPM_BUILD_ROOT/usr/share/man


mkdir -p %{buildroot}/etc/rc.d/init.d
mkdir -p %{buildroot}/etc/rc.d/rc{3,4}.d
mkdir -p %{buildroot}/usr/etc/dbus-1
cp %{SOURCE1} %{buildroot}/etc/rc.d/init.d/dbus-daemon_run
cp %{SOURCE2} %{buildroot}/etc/dbus-1/system.conf
chmod 644 %{buildroot}/etc/dbus-1/system.conf
chmod 755 %{buildroot}/etc/rc.d/init.d/dbus-daemon_run
ln -s ../init.d/dbus-daemon_run  %{buildroot}/etc/rc.d/rc3.d/S30dbus-daemon_run
ln -s ../init.d/dbus-daemon_run %{buildroot}/etc/rc.d/rc4.d/S30dbus-daemon_run

%post libs 
/sbin/ldconfig


%postun libs -p /sbin/ldconfig


%files
%manifest dbus.manifest
/etc/rc.d/init.d/*
/etc/rc.d/rc?.d/*
#/usr/etc/dbus-1/*
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
# dbus-daemon-launch-helper is not setuid in SLP
%{_libexecdir}/dbus-daemon-launch-helper
%{_libexecdir}/dbus-1
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/services
%{_datadir}/dbus-1/system-services
%dir %{_localstatedir}/run/dbus
%dir %{_localstatedir}/lib/dbus

%files libs
%manifest dbus.manifest
/%{_libdir}/libdbus-1.so.3*

%files devel
%manifest dbus.manifest
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc

