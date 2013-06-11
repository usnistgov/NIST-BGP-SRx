use ExtUtils::MakeMaker;
$Verbose = 1;
WriteMakefile(
                 NAME      => 'Net::Patricia::libpatricia',
                 SKIP      => [qw(all static static_lib dynamic dynamic_lib test)],
                 clean     => {'FILES' => 'libpatricia$(LIB_EXT)'},
);

sub MY::top_targets {
'
all :: static

test ::

static ::       libpatricia$(LIB_EXT)

libpatricia$(LIB_EXT): $(O_FILES)
	$(AR) cr libpatricia$(LIB_EXT) $(O_FILES)
	$(RANLIB) libpatricia$(LIB_EXT)

';
}
