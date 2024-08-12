! -*- bgp -*-
!
! QuaggaSRx BGPd sample configuration file
!
! $Id: bgpd.conf.sampleSRx,v 6.0 2021/04/12 14:55:38 ob Exp $
!
hostname bgpd
password zebra

router bgp 65000
  bgp router-id {IP_AS_65000}

  srx display
  srx set-proxy-id {IP_AS_65000}

  srx set-server 127.0.0.1 17900
  srx connect
  no srx extcommunity

  srx evaluation origin

  srx set-origin-value undefined

  srx policy origin local-preference valid    add      20 
  srx policy origin local-preference notfound add      10 
  srx policy origin local-preference invalid  subtract 20 


  no srx policy origin ignore undefined

  ! neighbor AS 65005
  neighbor {IP_AS_65005} remote-as 65005
  neighbor {IP_AS_65005} passive

  ! neighbor AS 65010
  neighbor {IP_AS_65010} remote-as 65010
  neighbor {IP_AS_65010} passive

  log stdout notifications
