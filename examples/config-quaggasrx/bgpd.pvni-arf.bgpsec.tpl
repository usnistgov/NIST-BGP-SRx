! -*- bgp -*-
!
! QuaggaSRx BGPd sample configuration file
!
! $Id: bgpd.conf.sampleSRx,v 5.1 2021/05/20 12:00:00 ob Exp $
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
  no srx extcommunity

  srx evaluation bgpsec distributed

  srx set-origin-value undefined
  srx set-path-value undefined

!
! Configure "Prefer Valid" using local preference
! Increase the local preference if route is valid.
!

! To assure that no local-pref will result in a non Valid
! route being selected over a valid route add prefer-valid
!
!  srx policy prefer-valid 

  srx policy local-preference valid       20 add
  srx policy local-preference invalid     20 subtract
  
  no srx policy ignore-undefined

srx bgpsec ski 0 1 8E232FCCAB9905C3D4802E27CC0576E6BFFDED64
srx bgpsec active 0


! Specify Neighbors
! =================
  ! neighbor AS 65005
  neighbor {IP_AS_65005} remote-as 65005
  neighbor {IP_AS_65005} ebgp-multihop
  neighbor {IP_AS_65005} passive
  neighbor {IP_AS_65005} bgpsec both
 
  ! neighbor AS 65010
  neighbor {IP_AS_65010} remote-as 65010
  neighbor {IP_AS_65010} ebgp-multihop
  neighbor {IP_AS_65010} passive
  neighbor {IP_AS_65010} bgpsec both

log stdout
