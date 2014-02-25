%define version 0.3.1.1
%define name quaggasrx

Name:%{name}
Version:%{version}
Release:	22%{?dist}
Summary:quagga summary

Group:Networking/Daemons
License:LGPL	
URL:www.antd.nist.gov		
Source0:%{name}-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:automake	
Requires:libc.so.6  libsrx.so.0

%description
quaggasrx rpm


%prep
%setup -q


%build
# %%configure \
#configure --build=i686-redhat-linux-gnu --host=i686-redhat-linux-gnu \
#    --target=i686-redhat-linux-gnu \
#    --program-prefix= \
#    --prefix=/usr \
#    --exec-prefix=/usr \
#    --bindir=/usr/bin \
#    --sbindir=/usr/sbin \
#    --sysconfdir=/etc \
#    --datadir=/usr/local/share \
#    --includedir=/usr/include \
#    --libdir=/usr/lib \
#    --libexecdir=/usr/libexec \
#    --localstatedir=/var \
#    --sharedstatedir=/var/lib \
#    --mandir=/usr/share/man \

./configure \
    --enable-user=root \
    --enable-group=root \
    --prefix=/usr \
    --sysconfdir=/etc \
    --enable-configfile-mask=0644 \
    --enable-logfile-mask=0644 \
    --enable-srx \
    --infodir=/usr/local/share/quaggasrx/info 
#   --no-create --no-recursion

make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc
   /etc/babeld.conf.sample
   /etc/bgpd.conf.sample
   /etc/bgpd.conf.sample2
   /etc/ospf6d.conf.sample
   /etc/ospfd.conf.sample
   /etc/ripd.conf.sample
   /etc/ripngd.conf.sample
   /etc/zebra.conf.sample
   /etc/bgpd.conf.sampleSRx
   /usr/include/quaggasrx/buffer.h
   /usr/include/quaggasrx/checksum.h
   /usr/include/quaggasrx/command.h
   /usr/include/quaggasrx/distribute.h
   /usr/include/quaggasrx/filter.h
   /usr/include/quaggasrx/getopt.h
   /usr/include/quaggasrx/hash.h
   /usr/include/quaggasrx/if.h
   /usr/include/quaggasrx/if_rmap.h
   /usr/include/quaggasrx/jhash.h
   /usr/include/quaggasrx/keychain.h
   /usr/include/quaggasrx/linklist.h
   /usr/include/quaggasrx/log.h
   /usr/include/quaggasrx/md5.h
   /usr/include/quaggasrx/memory.h
   /usr/include/quaggasrx/memtypes.h
   /usr/include/quaggasrx/network.h
   /usr/include/quaggasrx/ospfapi/ospf_apiclient.h
   /usr/include/quaggasrx/ospfd/ospf_api.h
   /usr/include/quaggasrx/ospfd/ospf_asbr.h
   /usr/include/quaggasrx/ospfd/ospf_dump.h
   /usr/include/quaggasrx/ospfd/ospf_ism.h
   /usr/include/quaggasrx/ospfd/ospf_lsa.h
   /usr/include/quaggasrx/ospfd/ospf_lsdb.h
   /usr/include/quaggasrx/ospfd/ospf_nsm.h
   /usr/include/quaggasrx/ospfd/ospf_opaque.h
   /usr/include/quaggasrx/ospfd/ospfd.h
   /usr/include/quaggasrx/plist.h
   /usr/include/quaggasrx/pqueue.h
   /usr/include/quaggasrx/prefix.h
   /usr/include/quaggasrx/privs.h
   /usr/include/quaggasrx/route_types.h
   /usr/include/quaggasrx/routemap.h
   /usr/include/quaggasrx/sigevent.h
   /usr/include/quaggasrx/smux.h
   /usr/include/quaggasrx/sockopt.h
   /usr/include/quaggasrx/sockunion.h
   /usr/include/quaggasrx/str.h
   /usr/include/quaggasrx/stream.h
   /usr/include/quaggasrx/table.h
   /usr/include/quaggasrx/thread.h
   /usr/include/quaggasrx/vector.h
   /usr/include/quaggasrx/version.h
   /usr/include/quaggasrx/vty.h
   /usr/include/quaggasrx/workqueue.h
   /usr/include/quaggasrx/zassert.h
   /usr/include/quaggasrx/zclient.h
   /usr/include/quaggasrx/zebra.h
   /usr/lib/libospf.a
   /usr/lib/libospf.la
   /usr/lib/libospf.so
   /usr/lib/libospf.so.0
   /usr/lib/libospf.so.0.0.0
   /usr/lib/libospfapiclient.a
   /usr/lib/libospfapiclient.la
   /usr/lib/libospfapiclient.so
   /usr/lib/libospfapiclient.so.0
   /usr/lib/libospfapiclient.so.0.0.0
   /usr/lib/libzebra.a
   /usr/lib/libzebra.la
   /usr/lib/libzebra.so
   /usr/lib/libzebra.so.0
   /usr/lib/libzebra.so.0.0.0
   /usr/sbin/babeld
   /usr/sbin/bgpd
   /usr/sbin/ospf6d
   /usr/sbin/ospfclient
   /usr/sbin/ospfd
   /usr/sbin/ripd
   /usr/sbin/ripngd
   /usr/sbin/watchquagga
   /usr/sbin/zebra
   /usr/local/share/quaggasrx/info/dir
   /usr/local/share/quaggasrx/info/quagga.info-1
   /usr/local/share/quaggasrx/info/quagga.info-2
   /usr/local/share/quaggasrx/info/quagga.info
   /usr/share/man/man8/bgpd.8.gz
   /usr/share/man/man8/ospf6d.8.gz
   /usr/share/man/man8/ospfclient.8.gz
   /usr/share/man/man8/ospfd.8.gz
   /usr/share/man/man8/ripd.8.gz
   /usr/share/man/man8/ripngd.8.gz
   /usr/share/man/man8/watchquagga.8.gz
   /usr/share/man/man8/zebra.8.gz



%changelog

