Name:       dbus
Summary:    D-Bus message bus
Version:    1.5.10
Release:    1
Group:      System/Libraries
License:    GPLv2+ or AFL
URL:        http://www.freedesktop.org/software/dbus/
Source0:    %{name}-%{version}.tar.gz
Source1:    dbus-user.socket
Source2:    dbus-user.service
Source1001: packaging/dbus.manifest 
Patch1:     0001-Enable-checking-of-smack-context-from-DBus-interface.patch
Patch2:     0002-Enforce-smack-policy-from-conf-file.patch
Patch3:     0003-dbus_service_highest_prio_setting.patch
Requires:   %{name}-libs = %{version}
BuildRequires:  expat-devel >= 1.95.5
BuildRequires:  gettext
BuildRequires:  libcap-devel
BuildRequires:  libtool
BuildRequires:  libx11-devel
BuildRequires:  pkgconfig(libsmack)


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

%patch1 -p1
%patch2 -p1
%patch3 -p1

%build
cp %{SOURCE1001} .


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
    --with-dbus-user=dbus \
    --with-systemdsystemunitdir=%{_libdir}/systemd/system \
    --enable-smack \
    --disable-systemd

make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}%{_libdir}/pkgconfig
# Change the arch-deps.h include directory to /usr/lib instead of /lib
sed -e 's@-I${libdir}@-I${prefix}/%{_lib}@' %{buildroot}%{_libdir}/pkgconfig/dbus-1.pc

mkdir -p %{buildroot}%{_datadir}/dbus-1/interfaces

mkdir -p %{buildroot}%{_libdir}/systemd/user
install -m0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/user/dbus.socket
install -m0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/user/dbus.service

%remove_docs


%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig


%files
%manifest dbus.manifest
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
%{_libdir}/systemd/system/*
%{_libdir}/systemd/user/*
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/interfaces
%{_datadir}/dbus-1/services
%{_datadir}/dbus-1/system-services
%dir %{_localstatedir}/run/dbus
%dir %{_localstatedir}/lib/dbus

%files libs
%manifest dbus.manifest
%{_libdir}/libdbus-1.so.3*

%files devel
%manifest dbus.manifest
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc

