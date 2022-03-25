"""
caida-to-bio - convert CAIDA topology file to input file for RPKI Cache test harness.


This file generaes an ASPA script file for the BGP-SRx RPKI Test Cache Harness
using the CAIDA AS relationship file. The CAIDA file structure presents the
data as:

         "PROVIDER|CUSTOMER|-1" ot "PEER|PEER|0".

This tool only used the -1 data and creates a RPKI Test Cache Harness file in
the format of:
 
         addASPA 0 CUSTOMER PROVIDER < PROVIDER>*

Tier one ASPA entries are listed in the file T1.txt. These are not added here.
These ASPA objects are added using the script ```generate-data.sh```


author: dougm@nist.gov

Version 0.1.0.0
"""
import sys, getopt
from datetime import datetime

def process_caida(infile, outfile, packbio, verbose):
    """process_caida read CAIDA topology file and convert to RPKI Cache Test Harness input file.

    The as-rel files contain p2p and p2c relationships.  The format is:
    <provider-as>|<customer-as>|-1
    <peer-as>|<peer-as>|0

    Args:
        infile (str): input file name
        outfile (str): output file name

    Returns:
        (int,int): record counts
    """
    inrec = 0
    outrec = 0
    aspa = {}
    histo = {}

    # open files
    try:
        ifile = open(infile,'r')
    except:
        print("Error trying to open <$s>" % infile)
    
    for line in ifile:
        #print(line)
        if line[0] == '#': # skip comments
            continue
        # parse CAIDA data - convert to integers
        providerAS,customerAS,rel = map(int, line.strip().split('|'))
        inrec +=1

        #print('<',providerAS, customerAS, rel,'>')

        # rel = -1 --> provider to customer?
        if rel == -1:
            if customerAS in aspa:
                aspa[customerAS].append(providerAS)
            else:
                aspa[customerAS] = [providerAS]
    ifile.close()

    # Generate sorted RPKI Cache Test Harness input file of ASPA data
    try:
        ofile = open(outfile,'w')
    except:
        print("Error trying to open <$s>" % outfile)

    for customer in sorted(aspa.keys()):
        # Build a histogram of multi-homing data
        numProviders = len(aspa[customer])
        if numProviders in histo:
            histo[numProviders] += 1
        else:
           histo[numProviders] = 1

        if packbio:
            print("addASPA 0 %d" % customer, end='', file=ofile)
            for provider in aspa[customer]:
                print(' %d' % provider, end='', file=ofile)
            print('', file=ofile)
            outrec += 1
        else:
           for provider in aspa[customer]:
                print("addASPA 0 %d %d" % (customer, provider), file=ofile)
                outrec +=1
    ofile.close()

    # Histogram of multihomed customers
    print("Histogram = %6d" % len(histo.keys()))
    if verbose:
        print("#Providers\t#Customers with ...")
        for pcount in sorted(histo.keys()):
            print("%5d \t\t%6d" % (pcount, histo[pcount]))
    else:
        print("Verbose = False")

    
    return (inrec, outrec)


def main(argv):
    """Convert CAIDA topology file to input file for RPKI Cache test harness.

    Args:
        argv argument list.
    """    
    inputfile = ''
    outputfile = ''

    packbio = False        # create packed ASPA entries.
    verbose = False

    syntax  = False

    try:
        prog = argv.pop(0)
        opts, args = getopt.getopt(argv,"hpvi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print (prog,' -i <inputfile> -o <outputfile>')
        sys.exit(2)
    # process options
    if len(opts) != 0:
        for opt, arg in opts:
            if opt == '-h':
                syntax = True
            elif opt in ("-i", "--ifile"):
                inputfile = arg
            elif opt in ("-o", "--ofile"):
                outputfile = arg
            elif opt == '-p':
                packbio = True
            elif opt == '-v':
                verbose = True 
    else:
        syntax = True

    if syntax:
        print ('\n\tSyntax: ', prog, ' -i <inputfile> -o <outputfile> [-p] [-v]\n')
        print ('\t       -p Pack the ASPA file\n')
        print ('\t       -v Add additional output\n')
        sys.exit()


    print('>>>', datetime.now(),'start: ',prog, " ".join(argv))
    # process the CAIDA file
    inrec, outrec = process_caida(inputfile, outputfile, packbio, verbose)
    # wrap up
    print('<<<', datetime.now(),'  end: ', prog, ' input records=',inrec, ' output records=', outrec)
    sys.exit()

if __name__ == "__main__":
   main(sys.argv)   
