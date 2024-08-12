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
  srx evaluation bgpsec distributed
  srx evaluation aspa

  srx set-origin-value undefined
  srx set-bgpsec-value undefined
  srx set-aspa-value undefined

  srx policy origin local-preference valid    add      20 
  srx policy origin local-preference notfound add      10 
  srx policy origin local-preference invalid  subtract 20 

  srx policy bgpsec local-preference valid   add      20 
  srx policy bgpsec local-preference invalid subtract 20 

  srx policy aspa local-preference valid        add      20
  srx policy aspa local-preference invalid      subtract 20 
  srx policy aspa local-preference unknown      add      10 
  srx policy aspa local-preference unverifiable subtract 5 

  no srx policy origin ignore undefined
  no srx policy bgpsec ignore undefined
  no srx policy aspa   ignore undefined

! Specify Neighbors
! =================
  srx bgpsec ski 0 1 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64
  srx bgpsec active 0

  ! neighbor AS 65005
  neighbor {IP_AS_65005} remote-as 65005
  neighbor {IP_AS_65005} passive
  neighbor {IP_AS_65005} bgpsec both
  neighbor {IP_AS_65005} aspa provider

  ! neighbor AS 65010
  neighbor {IP_AS_65010} remote-as 65010
  neighbor {IP_AS_65010} passive
  neighbor {IP_AS_65010} bgpsec both
  neighbor {IP_AS_65010} aspa lateral

  log stdout notifications
