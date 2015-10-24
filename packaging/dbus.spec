%bcond_with kdbus
%bcond_with kdbus_use_policy_library

# "enable foo" will turn into --enable-foo or --disable-foo
# depending "with_foo" macro
%define enable() %{expand:%%{?with_%{1}:--enable-%{1}}%%{!?with_%{1}:--disable-%{1}}}

Name:		dbus
Summary:	D-Bus message bus with kdbus support
Version:	1.8.16
Release:	1%{?release_flags}

Group:		System/Libraries
License:	GPL-2.0+ or AFL-2.1, BSD-2.0

#set 1 to switch on
%define with_platform_test	0

%if %{with_platform_test}
%define dbus_platform_test_dir /opt/platform-test/dbus
%endif

Source0:    	%{name}-%{version}.tar.gz
Source1:	dbus.service.in
Source2:	dbus-user.socket
Source3:	dbus-user.service
Source4:	dbus-user-kdbus.service
Source1001:	dbus.manifest
Source1002:     dbus.rule
BuildRequires:  which
BuildRequires:  expat-devel >= 1.95.5
BuildRequires:  libtool
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(libsmack)
%if 0%{with kdbus}
%if %{with kdbus_use_policy_library}
BuildRequires:  dbus-policy-devel
%endif
%endif

%description
D-Bus message bus with kdbus support
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
%if %{with kdbus_use_policy_library}
Requires:   %{name}-policy
%endif


%description devel
Headers and static libraries for D-Bus.

%if %{with_platform_test}
%package platform-test
Summary:    Samsung test tools for D-Bus.
Group:      System/Libraries
#FIXME: This is circular dependency
Requires:   %{name} = %{version}-%{release}

%description platform-test
Samsung test tools for D-Bus.
%endif

%prep
%setup -q -n %{name}-%{version}

%build
%if 0%{with kdbus}
cp %{SOURCE1} ./bus/
%endif
cp %{SOURCE1001} .

export CFLAGS+=" -fpie"
%if "%{?tizen_profile_name}" == "tv"
export CFLAGS+=" -DPROFILE_TV"
%endif
export LDFLAGS+=" -pie"

./autogen.sh --prefix=/usr
%reconfigure \
    --enable-verbose-mode \
    --enable-abstract-sockets --enable-x11-autolaunch --with-x \
    --enable-smack \
    --disable-static \
    --exec-prefix=/ \
    --bindir=%{_bindir} \
    --libexecdir=%{_libdir}/dbus-1 \
    --sysconfdir=%{_sysconfdir} \
    --libdir=%{_libdir} \
    --includedir=%{_includedir} \
    --localstatedir=%{_localstatedir} \
    --datadir=%{_datadir} \
    --docdir=%{_docdir} \
    --disable-asserts \
    --disable-xml-docs \
    --disable-selinux \
    --disable-libaudit \
    --enable-tests=no \
%if "%{?tizen_profile_name}" == "tv"
    --with-system-pid-file=/tmp/dbus_launch \
%else
    --with-system-pid-file=%{_localstatedir}/run/messagebus.pid \
%endif
    --with-dbus-user=root \
    --with-systemdsystemunitdir=%{_libdir}/systemd/system \
%if 0%{with kdbus}
    --enable-kdbus-transport \
    --with-system-default-bus=kernel:path=/dev/kdbus/0-system/bus \
    --with-dbus-session-bus-listen-address=kernel: \
    --with-dbus-session-bus-connect-address=kernel:path=/dev/kdbus/5000-user/bus \
    --enable-match-in-lib=yes \
    --enable-smack-labeled-bus \
%if %{with kdbus_use_policy_library}
    --enable-policy-in-lib \
%endif
%endif

# When compiled using gbs with --enable-abstract-sockets param autogen.sh creates a config.h in
# /GBS-ROOT/local/BUILD-ROOTS/scratch.armv7l.0 with # /* #undef HAVE_ABSTRACT_SOCKETS */.
# Code changes it to #define HAVE_ABSTRACT_SOCKETS 1.
if grep -q "#define HAVE_ABSTRACT_SOCKETS\s1" config.h; then
	echo HAVE_ABSTRACT_SOCKETS found.
else
	echo HAVE_ABSTRACT_SOCKETS not found. Adding it.
	sed -i 's/\/\* #undef HAVE_ABSTRACT_SOCKETS \*\//#define HAVE_ABSTRACT_SOCKETS 1/' config.h
fi

make %{?jobs:-j%jobs}

%install
%make_install
%remove_docs

mkdir -p %{buildroot}%{_libdir}/pkgconfig
# Change the arch-deps.h include directory to /usr/lib instead of /lib
sed -e 's@-I${libdir}@-I${prefix}/%{_lib}@' %{buildroot}%{_libdir}/pkgconfig/dbus-1.pc

mkdir -p %{buildroot}%{_datadir}/dbus-1/interfaces

# We will not allow shipping dbus-monitor on user image.
%if ! 0%{?tizen_build_binary_release_type_eng:1}
rm -fr $RPM_BUILD_ROOT%{_bindir}/dbus-monitor
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/user
install -m0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/user/dbus.socket
%if 0%{with kdbus}
install -m0644 %{SOURCE4} %{buildroot}%{_libdir}/systemd/user/dbus.service
%else
install -m0644 %{SOURCE3} %{buildroot}%{_libdir}/systemd/user/dbus.service
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/user/sockets.target.wants
mkdir -p %{buildroot}%{_libdir}/systemd/user/default.target.wants
ln -sf ../dbus.socket %{buildroot}%{_libdir}/systemd/user/sockets.target.wants/dbus.socket
ln -sf ../dbus.service %{buildroot}%{_libdir}/systemd/user/default.target.wants/dbus.service

mkdir -p %{buildroot}/etc/smack/accesses.d
install -m0644 %{SOURCE1002} %{buildroot}/etc/smack/accesses.d/dbus.rule

mkdir -p %{buildroot}%{_libdir}/udev/rules.d/
cp -a packaging/70-kdbus.rules %{buildroot}%{_libdir}/udev/rules.d/

%if %{with_platform_test}
make -C samsung_tools install-samsung-tools DESTDIR=%{buildroot}%{dbus_platform_test_dir}
%endif

mkdir -p $RPM_BUILD_ROOT%{_datadir}/license
cat COPYING > $RPM_BUILD_ROOT%{_datadir}/license/dbus
cat LICENSE >> $RPM_BUILD_ROOT%{_datadir}/license/dbus
cat COPYING > $RPM_BUILD_ROOT%{_datadir}/license/dbus-libs
cat LICENSE >> $RPM_BUILD_ROOT%{_datadir}/license/dbus-libs

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
%if 0%{?tizen_build_binary_release_type_eng:1}
%{_bindir}/dbus-monitor
%endif
%{_bindir}/dbus-send
%{_bindir}/dbus-uuidgen
%{_bindir}/dbus-launch
%{_bindir}/dbus-run-session
%{_bindir}/dbus-test-tool
%dir %{_sysconfdir}/dbus-1
%config %{_sysconfdir}/dbus-1/session.conf
%dir %{_sysconfdir}/dbus-1/session.d
%config %{_sysconfdir}/dbus-1/system.conf
%dir %{_sysconfdir}/dbus-1/system.d
%dir %{_libdir}/dbus-1
%attr(4750,root,dbus) %{_libdir}/dbus-1/dbus-daemon-launch-helper
%{_libdir}/systemd/system/dbus.service
%{_libdir}/systemd/system/multi-user.target.wants/dbus.service
%{_libdir}/systemd/user/dbus.service
%{_libdir}/systemd/user/default.target.wants/dbus.service
%{_libdir}/systemd/system/dbus.socket
%{_libdir}/systemd/system/dbus.target.wants/dbus.socket
%{_libdir}/systemd/system/sockets.target.wants/dbus.socket
%{_libdir}/systemd/user/dbus.socket
%{_libdir}/systemd/user/sockets.target.wants/dbus.socket
%dir %{_datadir}/dbus-1
%{_datadir}/dbus-1/interfaces
/etc/smack/accesses.d/dbus.rule
%{_libdir}/udev/rules.d/70-kdbus.rules
%{_datadir}/dbus-1/services
%{_datadir}/dbus-1/system-services
%dir %{_localstatedir}/run/dbus
%dir %{_localstatedir}/lib/dbus
%manifest dbus.manifest

%files libs
%defattr(-,root,root,-)
%{_datadir}/license/dbus-libs
%{_libdir}/libdbus-1.so.3*
%exclude %{_libdir}/libdbuspolicy-1.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libdbus-1.so
%{_includedir}/dbus-1.0/dbus/dbus*.h
%if %{with kdbus}
%endif
%dir %{_libdir}/dbus-1.0
%{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%{_libdir}/pkgconfig/dbus-1.pc
%exclude %{_libdir}/pkgconfig/dbus-policy.pc
%exclude %{_libdir}/libdbuspolicy-1.so

%if %{with_platform_test}
%files platform-test
%{dbus_platform_test_dir}/*
%endif
