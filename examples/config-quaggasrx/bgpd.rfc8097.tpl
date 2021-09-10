! -*- bgp -*-
!
! QuaggaSRx BGPd sample configuration file
!
! $Id: bgpd.conf.sampleSRx,v 6.0 2021/04/12 14:55:38 ob Exp $
!
hostname bgpd
password zebra

!
!bgp multiple-instance
!
router bgp 65000
  bgp router-id 10.0.0.65

  srx display
  srx set-proxy-id 10.0.0.65
  srx set-server 127.0.0.1 17900
  srx connect

  srx evaluation origin

  srx set-origin-value undefined

  srx policy origin local-preference valid    add      20 
  srx policy origin local-preference notfound add      10 
  srx policy origin local-preference invalid  subtract 20 

!
!  Enable ROV validation signaling, to include 
!  experimental ebgp add include_ebgp
!
  srx extcommunity 200

! Specify Neighbors
! =================
! I-BGP Session
 neighbor {IP_AS_65000-00} remote-as 65000
 neighbor {IP_AS_65000-00} ebgp-multihop
 neighbor {IP_AS_65000-00} passive
 
 neighbor {IP_AS_65010} remote-as 65010
 neighbor {IP_AS_65010} ebgp-multihop
 neighbor {IP_AS_65010} passive

log stdout
