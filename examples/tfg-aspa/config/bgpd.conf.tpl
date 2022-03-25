! -*- bgp -*-
!
! QuaggaSRx BGPd sample configuration file
!
! $Id: bgpd.conf.sampleSRx,v 6.0 2021/04/12 14:55:38 ob Exp $
!
hostname bgpd
password zebra
!enable password please-set-at-here
!
!bgp multiple-instance
!
router bgp 65000
  bgp router-id 10.0.0.1


!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! QuaggaSRx Configuration Extension  
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  srx set-proxy-id 10.0.0.1
  srx set-server 127.0.0.1 17900
  srx connect

  srx evaluation aspa
  srx set-aspa-value undefined

  no srx policy origin ignore undefined
  no srx policy bgpsec ignore undefined
  no srx policy aspa ignore undefined

  neighbor {PEER_IP} remote-as {PEERING_AS}
  neighbor {PEER_IP} passive
  neighbor {PEER_IP} aspa {PEERING_RELATION}

  !log file bgpd.log
  log stdout
