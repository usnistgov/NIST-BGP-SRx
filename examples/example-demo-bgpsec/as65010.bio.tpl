ski_file    = "../opt/bgp-srx-examples/example-demo-bgpsec/ski-list.as65010.txt";
ski_key_loc = "../opt/bgp-srx-examples/bgpsec-keys/";

preload_eckey = false;
mode = "BGP";
max = 0;
only_extended_length = true;
appendOut = "false";

session = (
  {
    asn        = 65010;
    bgp_ident  = "{IP_AS_65010}";
    hold_timer = 180;

    local_addr = "{IP_AS_65010}";

    peer_asn   = 65000;
    peer_ip    = "{IP_AS_65000-10}";
    peer_port  = 179;

    disconnect = 0;
    convergence = false;
    ext_msg_cap = false;
    ext_msg_liberal = false;

    bgpsec_v4_snd = true;
    bgpsec_v4_rcv = true;
    bgpsec_v6_snd = true;
    bgpsec_v6_rcv = true;

    # (path prefix B4 specifies BGP4 only update!)
    # <prefix>[,[[B4]? <asn>[p<repetition>]]*[ ]*[I|V|N]?]
    #
    #
    #  Topology:  
    #                                 /---65025
    #                                /
    #            65000---65010---65020----65030
    #                                \
    #                                 \---65040
    #
    #
    update = (  
              "10.10.0.0/20"   
              ,"10.10.32.0/19,  {65011 65012}"
              ,"10.10.128.0/17, {65013 65014}"
              ,"10.20.0.0/20,   65020"
              ,"10.25.0.0/21,   65020 65025"
              ,"10.25.0.0/22,   65020 65025"
              ,"10.30.0.0/22,   65020 65030"
              ,"10.30.0.0/23,   65020 65030"
              ,"10.40.0.0/22,   65020 65040"
             );

    incl_global_updates = true;
    prefixPacking = false;

    algo_id = 1;
    signature_generation = "BIO-K1";

    null_signature_mode = "FAKE";
    fake_signature      = "1BADBEEFDEADFEED" "2BADBEEFDEADFEED"
                          "3BADBEEFDEADFEED" "4BADBEEFDEADFEED"
                          "5BADBEEFDEADFEED" "6BADBEEFDEADFEED"
                          "7BADBEEFDEADFEED" "8BADBEEFDEADFEED"
                          "ABADBEEFFACE";
    fake_ski            = "0102030405060708" "090A0B0C0D0E0F10"
                          "11121314";

    printOnSend = {
      update       = true;
    };

    printOnReceive = false;

    printSimple    = true;
    printPollLoop  = false;
    printOnInvalid = false;

  }
);
update = ( 
         );
