%bcond_with kdbus
%define release_flags %{?with_kdbus:+kdbus}

# "enable foo" will turn into --enable-foo or --disable-foo
# depending "with_foo" macro
%define enable() %{expand:%%{?with_%{1}:--enable-%{1}}%%{!?with_%{1}:--disable-%{1}}}

Name:		dbus-policy
Summary:        A helper library for fine-grained userspace policy handling
Group:          System/Libraries
Version:	1.8.16
Release:	1%{?release_flags}

Group:		System/Libraries
License:	GPL-2.0+ or AFL-2.1, BSD-2.0

Source0:    	http://dbus.freedesktop.org/releases/dbus/dbus-%{version}.tar.gz
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

%description
libdbuspolicy is a helper library for fine-grained userspace
policy handling (with SMACK support)

%package devel
Summary:  Development files for libdbuspolicy
Requires:   %{name} = %{version}-%{release}

%description devel
Development files for libdbuspolicy

%prep
%setup -q -n dbus-%{version}

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

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libdbuspolicy-1.so.*
%exclude %{_libdir}/libdbus-1.so*
%exclude %{_sysconfdir}/dbus-1/session.conf
%exclude %{_sysconfdir}/dbus-1/system.conf
%exclude %{_sysconfdir}/smack/accesses.d/dbus.rule
%exclude %{_bindir}/*
%exclude %{_includedir}/dbus-1.0/dbus/*
%exclude %{_libdir}/dbus-1.0/include/dbus/dbus-arch-deps.h
%exclude %{_libdir}/dbus-1/dbus-daemon-launch-helper
%exclude %{_libdir}/pkgconfig/dbus-1.pc
%exclude %{_libdir}/pkgconfig/dbus-policy.pc
%exclude %{_libdir}/systemd/*
%exclude %{_libdir}/udev/rules.d/70-kdbus.rules
%files devel
%defattr(-,root,root,-)
%{_includedir}/dbus-1.0/dbus/dbus-policy.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-address.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-bus.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-connection.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-errors.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-macros.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-memory.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-message.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-misc.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-pending-call.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-protocol.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-server.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-shared.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-signature.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-syntax.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-threads.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus-types.h
%exclude %{_includedir}/dbus-1.0/dbus/dbus.h
%{_libdir}/pkgconfig/dbus-policy.pc
%{_libdir}/libdbuspolicy-1.so
