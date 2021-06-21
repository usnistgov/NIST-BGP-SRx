Examples for Router Configurations
==================================

The set of configurations below will provide a small set of 
possibilities but shoulg give enough insight on how to pursue
certain configuration outcomes.


* Prefer Valid (pv)

  QuaggaSRx allows mutliple forms of implementing a prefer valid policy.
  With prefer valid we mean valid versus anything else. To routes that are 
  not valid will be chosen on factors other than validation.

  Using 'prefer-valid' switch from (swf)
  ---------------------------------------
  Implemented in bgpd.pv-swf.[bgpsec|origin].conf

  Using 'local preference' form (lpf)
  -----------------------------------
  Implemented in bgpd.pv-lpf.[bgpsec|origin].conf


* Prefer Valid over NotFound over Invalid (pvni)

  Not using the 'prefer-valid' switch, this can be achieved using 
  an arithmetic form as well as setting form.
  Arithmetic means the local preference will be recalculated and 
  modified according to the validation state. The setting form
  will overwrite the configuration.

  The following examples ONLY use local preference. The arithmetic 
  form (arf) is used to increase or decrease the already determined 
  local preference. This is done by choosing a delta value to add or 
  subtract from the local pref. This form very much depends on the 
  initial local pref and could still result in an invalid route 
  being selected over any other route. 
  For instance an invalid route A with a local pref of 200 and a 
  subtraction of 20 would result in a local pref of 180.
  Now a valid route B with a local pred of 100 and an addition of 20
  would only result in a local pref of 120. Here the invalid route 
  still would be chosen over the valid route. 
  There are two different approaches to mitigate this issue:
  - Add switch 'prefer-valid'
  - Use the set form rather than the arithmetic form

  To prevent this from happening local pref based policies always can 
  include the 'prefer-valid' switch

  Using arithmetic form (arf)
  ---------------------------
  Implemented in bgpd.pvni-arf.[bgpsec|origin].conf


  The following examples overwrite the local preference depending on the 
  validation result. This is done using the set form (sef) where the new
  local preference is specified.

  Using set form (sef)
  --------------------
  Implemented in bgpd.pvni-sef.[bgpdec|origin].conf


* Activate signaling of origin validation

  Using RFC 8097
  --------------
  Implemented in bgpd.rfc8097.conf
  
  Even though this setting can be used not only with origin validation but also
  with the bgpsec validation setting, for simplicity we only add one example.
