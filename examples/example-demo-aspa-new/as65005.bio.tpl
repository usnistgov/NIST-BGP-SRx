ski_file    = "../opt/bgp-srx-examples/bgpsec-keys/ski-list.txt";
ski_key_loc = "../opt/bgp-srx-examples/bgpsec-keys/";

preload_eckey = false;

mode = "BGP";
max = 0;

only_extended_length = true;
appendOut = "false";

session = (
  {
    asn        = 65005;
    bgp_ident  = "{IP_AS_65005}";
    hold_timer = 180;

    local_addr = "{IP_AS_65005}";

    peer_asn   = 65000;
    peer_ip    = "{IP_AS_65000-05}";
    peer_port  = 179;

    disconnect = 0;
    convergence = false;
    ext_msg_cap = false;
    ext_msg_liberal = false;

    bgpsec_v4_snd = false;
    bgpsec_v4_rcv = false;
    bgpsec_v6_snd = false;
    bgpsec_v6_rcv = false;

    # (path prefix B4 specifies BGP4 only update!)
    # <prefix>[,[[B4]? <asn>[p<repetition>]]*[ ]*[I|V|N]?]
    #
    #  Topology:  65030---65025---65010---65015
    #               |               |       \
    #               |               |        \
    #             65040           65005     65020
    #          10.40.0.0/22       (BIO)  10.20.0.0/22
    #                               |
    #                             65000
    #                             (IUT)
    #
    update = (  
              "10.40.0.0/22,    B4 65010 65025 65030 65040"
              ,"10.20.0.0/22,   B4 65010 65015 65020"
             );

    incl_global_updates = true;
    prefixPacking = true;

    algo_id = 1;

    signature_generation = "BIO";
    null_signature_mode = "BGP4";
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
  }
);
update = ( 
         );
