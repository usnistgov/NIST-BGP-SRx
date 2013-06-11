use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::Patricia',
    'VERSION_FROM' => 'Patricia.pm', # finds $VERSION
    'LIBS'	=> ['-lnsl'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
    'MYEXTLIB'	=> 'libpatricia/libpatricia$(LIB_EXT)',     # e.g., '-I/usr/include/other' 
    'dist'      => {'COMPRESS'=>'gzip -9f', 'SUFFIX' => 'gz'},
);

sub MY::postamble {
'
$(MYEXTLIB): libpatricia/Makefile
	cd libpatricia && $(MAKE) $(PASTHRU)
';
}
