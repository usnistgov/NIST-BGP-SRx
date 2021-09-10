verbose  = true;
loglevel = 5;

sync    = true;
port    = 17900;

console: {
  port = 17901;
  password = "x";
};

rpki: {
  host = "localhost";
  port = 50000;
  router_protocol = 2;
};

bgpsec: {
  srxcryptoapi_cfg = "../opt/bgp-srx-examples/example-demo-all/srxcryptoapi-srx-server.conf";
  sync_logging = true;
};

mode: {
  no-sendqueue = true;
  no-receivequeue = false;
};

mapping: {
  client_65 = "{IP_AS_65000}";
};
