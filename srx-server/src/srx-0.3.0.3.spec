%define version 0.3.0.3
%define name srx
%define lconf_name libconfig
%define lconf_version 1.4.1
%define lpatr_name Net-Patricia
%define lpatr_version 1.15

Name:%{name}
Version:%{version}
Release:	1%{?dist}
Summary:srx Summary

Group:Networking/Daemons
License:LGPL	
URL:www.antd.nist.gov
Source0:%{name}-%{version}.tar.gz
Source1:%{lconf_name}-%{lconf_version}.tar.gz
Patch: Net-Patricia-1.15-fixes-20100513.patch
BuildRoot:/tmp/rpm/%{name}-%{version}	
#%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Prefix:/usr/local/srx

BuildRequires:automake	
Requires:glibc libconfig >= 1.3

%description
srx rpm packaging file


%prep
%setup -q
#%setup -q -D -T -a 1 
cd extras
/usr/bin/gzip -dc $RPM_SOURCE_DIR/%{lconf_name}-%{lconf_version}.tar.gz | tar -xvvf - > /dev/null
/usr/bin/gzip -dc $RPM_SOURCE_DIR/%{lpatr_name}-%{lpatr_version}.tar.gz | tar -xvvf - > /dev/null
STATUS=0

echo "Patch #0"
cd %{lpatr_name}-%{lpatr_version}/libpatricia
%patch -p0
#patch -p0 -i $RPM_SOURCE_DIR/%{lpatr_name}-%{lpatr_version}-fixes-20100513.patch


%build
%configure --with-libpatr --with-libconf --sysconfdir=/etc
#./configure --prefix=/usr --with-libpatr --with-libconf
make %{?_smp_mflags}
pwd
cd extras/%{lconf_name}-%{lconf_version}
./configure --prefix=/usr/local --disable-cxx
make

cd ../%{lpatr_name}-%{lpatr_version}/libpatricia
perl Makefile.PL
make
pwd
cp -f libpatricia.a ../../


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
pwd
cd extras/%{lconf_name}-%{lconf_version}
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT

%post
ldconfig

%files
%defattr(-,root,root,-)
%doc
/usr/lib/srx/libsrx_packets.so.0.0.0
/usr/lib/srx/libsrx_packets.so.0
/usr/lib/srx/libsrx_packets.so
/usr/lib/srx/libsrx_packets.la
/usr/lib/srx/libsrx_packets.a
/usr/lib/srx/libsrxutil.so.0.0.0
/usr/lib/srx/libsrxutil.so.0
/usr/lib/srx/libsrxutil.so
/usr/lib/srx/libsrxutil.la
/usr/lib/srx/libsrxutil.a
/usr/lib/srx/libsrx.so.0.0.0
/usr/lib/srx/libsrx.so.0
/usr/lib/srx/libsrx.so
/usr/lib/srx/libsrx.la
/usr/lib/srx/libsrx.a
/etc/srx_server.conf
/etc/ld.so.conf.d/srx_lib.conf
/usr/bin/srx_server
/usr/bin/rpkirtr_client
/usr/bin/rpkirtr_svr
/usr/bin/srxsvr_client
/usr/include/patricia.h
/usr/include/uthash.h
/usr/include/srx/uthash.h
/usr/include/srx/types.h
/usr/include/srx/srx_defs.h
/usr/include/srx/srx_api.h
/usr/include/srx/slist.h
/usr/include/srx/prefix.h
/usr/local/lib/libconfig.so.9.0.1
/usr/local/lib/libconfig.so.9
/usr/local/lib/libconfig.so
/usr/local/lib/libconfig.la
/usr/local/lib/libconfig.a
/usr/local/include/libconfig.h
/usr/local/lib/pkgconfig/libconfig.pc
/usr/local/share/info/dir
/usr/local/share/info/libconfig.info


