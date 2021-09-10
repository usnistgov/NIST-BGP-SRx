Examples for Router Configurations
==================================

The set of configurations below will provide a small set of 
possibilities but shoulg give enough insight on how to pursue
certain configuration outcomes.

* Prefer Valid over NotFound over Invalid (pvni)

  This can be done in an arithmetic form by adding or subtracting 
  a calculated value from the local pref depending on the validation 
  state of each performed validation.

  The following examples only use local preference. The arithmetic 
  form (arf) could still result in an invalid route selected over
  any other route. The reason is that this form recalculates the 
  local pref by increasing or decreasing the already specified local 
  preference. This can lead to the situation were a valid route's new
  local prev value is still less then the competing 'invalid' route due 
  to the difference of local pref due to previous policy decisions.

  Using arithmetic form (arf)
  ---------------------------
  Implemented in bgpd.pvni-arf.[bgpdec|origin|aspa].conf

* Activate signaling of origin validation

  Using RFC 8097
  --------------
  Implemented in bgpd.rfc8097.conf
  
  Even though this setting can be used not only with origin validation but also
  with the bgpsec validation setting, for simplicity we only add one example.