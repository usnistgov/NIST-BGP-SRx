# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; $debug = 1; print "1..19\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Patricia;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

print ref($t = new Net::Patricia)? "ok 2\n" : "not ok 2\n";

print $t->add_string('127.0.0.0/8')? "ok 3\n" : "not ok 3\n";

if ('127.0.0.0/8' eq $t->match_string("127.0.0.1")) {
   print "ok 4\n"
} else {
   print "not ok 4\n"
}

if ('127.0.0.0/8' eq $t->match_integer(2130706433)) { # 127.0.0.1
   print "ok 5\n"
} else {
   print "not ok 5\n"
}

if (!$t->match_string("10.0.0.1")) {
   print "ok 6\n"
} else {
   print "not ok 6\n"
}

if (!$t->match_integer(42)) {
   print "ok 7\n"
} else {
   print "not ok 7\n"
}

{
   my $ten = new Thingy 10;
   my $twenty = new Thingy 20;
print $t->add_string('10.0.0.0/8', $ten)? "ok 8\n" : "not ok 8\n";
}

print("Destructor 10 should *not* have run yet.\n") if $debug;

foreach my $subnet (qw(10.42.42.0/31 10.42.42.0/26 10.42.42.0/24 10.42.42.0/32 10.42.69.0/24)) {
   $t->add_string($subnet) || die
}

die if $t->match_string('10.42.42.0/24') eq $t->match_string('10.42.69.0/24');

if (10 == ${$t->match_integer(168430090)}) { # 10.10.10.10
   print "ok 9\n"
} else {
   print "not ok 9\n"
}

if ($t->match_string("10.0.0.1")) {
   print "ok 10\n"
} else {
   print "not ok 10\n"
}

if (!$t->match_exact_integer(167772160)) { # 10.0.0.0
   print "ok 11\n"
} else {
   print "not ok 11\n"
}

if ($t->match_exact_integer(167772160, 8)) { # 10.0.0.0
   print "ok 12\n"
} else {
   print "not ok 12\n"
}

if (10 == ${$t->match_exact_string("10.0.0.0/8")}) {
   print "ok 13\n"
} else {
   print "not ok 13\n"
}

if (!$t->remove_string("42.0.0.0/8")) {
   print "ok 14\n"
} else {
   print "not ok 14\n"
}

if (10 == ${$t->remove_string("10.0.0.0/8")}) {
   print "ok 15\n"
} else {
   print "not ok 15\n"
}

print("Destructor 10 should have just run.\n") if $debug;

if (!$t->match_exact_integer(167772160, 8)) { # 10.0.0.0
   print "ok 16\n"
} else {
   print "not ok 16\n"
}

# print "YOU SHOULD SEE A USAGE ERROR HERE:\n";
# $t->match_exact_integer(167772160, 8, 10);

if (6 == $t->climb_inorder(sub { print "climbing at $_[0]\n" })) {
   print "ok 17\n"
} else {
   print "not ok 17\n"
}

$t->climb;

eval '$t->add_string("_")'; # invalid key
if ($@ && $@ =~ m/invalid/i) {
   print "ok 18\n"
} else {
   print "not ok 18\n"
}

$t->add_string('0/0');

print $t->match_string("10.0.0.1")?"ok 19\n":"not ok 19\n";

undef $t;

exit;

package Thingy;

sub new {
   my $class = shift(@_);
   my $self = shift(@_);
   return bless \$self, $class
}

sub DESTROY {
   my $self = shift(@_);
   print("$$self What a world, what a world...\n")
}
