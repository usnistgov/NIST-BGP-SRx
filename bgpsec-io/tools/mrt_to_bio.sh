#/bin/s
case "$1" in
  "" | "?" | "h")
    echo "Syntax: $0 <mrt file> [-o outfile] [num-updates]"
    echo "num-updates: number of updates or all if not specified"
    exit 0;
    ;;
  *)
    ;;
esac

mrt_file="$1"
out_file="$1"

shift

while [ "$1" != "" ] ; do
  case "$1" in 
    "-o")
      shift
      out_file=$1
      ;;
    *)
      N=$1;
      ;;
  esac
  shift
done

$B4="B4 "

if [ ! -e ./bgpdump ] ; then
  echo "bgpdump is needed to generate the traffic."
  exit 1
fi

if [ $N -gt 0 ] ; then
  echo "Create BGP traffic for $N updates"
  ./bgpdump -m $mrt_file | head -n $N | sed -e "s/\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\(.*\)/\6, $B4\7/g" > $out_file.updates
else
  echo "Create BGP traffic for all updates"
  ./bgpdump -m $mrt_file | sed -e "s/\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\([^|]*\)|\(.*\)/\6, $B4\7/g" > $out_file.updates
fi

echo "Create ROAs"
cat $out_file.updates | sed -e "s/\(.*\)\/\([0-9]*\),.*\( [0-9\.]*\)/add \1\/\2 \2 \3/g" | sort -u > $out_file.roa

echo "Create ASN list for keys"
cat $out_file.updates | sed -e "s/.*,//g" | sed -e "s/ /\n/g" | sed -e "s/ //g" | sed "/^$/d" | sort -u -g > $out_file.asn
