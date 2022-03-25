#!/bin/bash
#
# This script together with the find-peer.sh script identifies which collectors
# are peering with a given autonomous system (AS). Once one or more collectors
# are identified the MRT formated RIB dumps are downloaded and only the BGP data
# concerning the identified ASN are extracted. In particular only the AS Path.
# Because the AS path information is the one of the collector only portions that
# are shared with the collector are extracted. To get the most amount of routes
# known to the ASN in question, the MRT files of all collectors peering with the 
# requested ASN are downloaded.
#
# Once the AS Path information is extracted, the AS which is the AS in question is 
# removed. All found AS path information is sorted and duplicates are discarded.
#
# At this point, this tool does not remove duplicates within a AS path.
#
# The final result is stored in the file 'ANS.txt'
#
# Specify the default data file
#
# Version 0.1.0.0
#
data_year="$(date +%Y)"
data_month="$(date +%m)"
data_day="$(date +%d)"
data_time="0000"

# The AS number for which the AS Pasth data will be retrieved
data_asn=""

# Indicates if the .raw files should be removed after usage (default: keep)
clean_raw=0
# Indicates if the mrt .bz2 files should be removed after usage (default: keep)
clean_mrt=0

# Folder where the RIB MRT files are stored
rib_fldr="mrt-rib"

#
# This function verifies the given date values.
# in case the date values are incorrect, the script exits the program (1)
# $1 the name of the field $2 the field value
#
function check_data()
{
  _regex="^$"
  case "$1" in
    "year")  _regex="^2[0-2][0-9]\{2,2\}$" ;;
    "month") _regex="^[0-1][0-9]$" ;;
    "day")   _regex="^[0-3][0-9]$" ;;
    "time")  _regex="^[0-2][0-9][0-5][0-9]$" ;;
    *) ;;
  esac
  echo $2 | grep -e "$_regex"
  if [ ! $? -eq 0 ] ; then
    echo "Invalid $1 '$2' in data!"
    exit 1
  fi
}

#
# Print the programs syntax and exit (0)
#
function syntax()
{
  echo "$0 [-y <year YYYY>] [-m <month MM>] [-d <dat DD>] [-t <time HHMM>] [-cr|--clean-raw] [-cm|--clear-mrt] <ASN>"
  echo "$0 [options] <ASN>"
  echo "  Options:"
  echo "    Date of the file to be downloaded. (By default today at midnight 0000)"
  echo "      -y <year>   The year in YYYY format."
  echo "      -m <month>  The month in MM number format (01-12)."
  echo "      -d <day>    The day in DD number format (00-31)."
  echo "      -t <time>   The time in HHMM format."
  echo "    Cleanup options"
  echo "      -cr, --clean-raw   Remove all generated .raw files."
  echo "      -cm, --clear-mrt   Remove all downloaded mrt .bz2 files."
  echo
  exit
}

while [ "$1" != "" ] ; do
  case "$1" in
    "-cr" | "--clean-raw") clean_raw=1 ;;
    "-cm" | "--clean-mrt") clean_raw=1 ;;
    "-?" | "-h") syntax ;;                 
    "-y") shift
          data_year="$1"
          check_data "year" $1
          ;;
    "-m") shift
          data_month="$1"
          check_data "month" $1
          ;;
    "-d") shift
          data_day="$1"
          check_data "day" $1
          ;;
    "-t") shift
          data_time="$1"
          check_data "time" $1
          ;;
    *)    if [ "$sdata_asn" == "" ] ; then
            echo "$1" | grep -e "^[0-9][0-9\.]*$" > /dev/null
            if [ $? -eq 0 ] ; then
              data_asn=$1
            else
              echo "Invalid AS parameter '$1'"
              exit 1;
            fi
          else
            echo "Lookup only a single AS!"
            exit 1;
          fi
  esac
  shift
done

if [ "$data_asn" == "" ] ; then
  echo "No ASN specified!"
  exit 1
fi

echo "Process MRT data for '$data_year/$data_month/$data_day $data_time'"

mrt_file="rib.$data_year$data_month$data_day.$data_time.bz2"
peer_file="$data_asn.raw"
urls=( $(./find-peer.sh $data_asn) )

echo "${#urls[@]} archives with RIB data for AS $data_asn found!"
if [ ${#urls[@]} -eq 0 ] ; then
  exit 1
fi

for url in ${urls[@]} ; do
  echo "  - $url"
done

mrt_files=()
for url in ${urls[@]} ; do
  echo "* Process URL: '$url'"
  file_prefix=$(echo $url | sed -e "s#http://archive.routeviews.org##g" | sed -e "s#/##g")
  file_url="$url/bgpdata/$data_year.$data_month/RIBS/$mrt_file"
  download_file="$rib_fldr/$(echo "$file_prefix.$mrt_file" | sed -e "s/^\.//g")"
  if [ ! -r "$rib_fldr" ] ; then
    mkdir $rib_fldr
  fi
  if [ ! -e "$download_file" ] ; then
    echo "  - Copy MRT dump file '$file_url' into '$download_file'..."
    wget "$file_url" --output-document $download_file
    if [ $? -eq 0 ] ; then
      mrt_files+=( $download_file )
    else
      echo "  - Error downloading '$download_file'"
    fi
  else
    echo "  - Data file '$download_file' already available, no download needed!"
    mrt_files+=( $download_file )
  fi
done

echo "Create file info '$data_asn-mrt-files.txt'"
echo > $data_asn-mrt-files.txt
for mrt_file in ${mrt_files[@]} ; do
  echo "$mrt_file" >> $data_asn-mrt-files.txt
done

#########################################################
## Now process each file
#########################################################
raw_file="$data_asn.raw"
sort_file="$data_asn.sort"
out_file="$data_asn.txt"
echo -n > $sort_file
echo -n > $out_file
file_num=1
stage=0
start_time=$(date +%s)
for mrt_file in ${mrt_files[@]} ; do
  raw_file="$data_asn.$file_num.raw"
  ((stage++))
  if [ -e $mrt_file ] ; then
    echo
    echo "Process $file_num. MRT dump file '$mrt_file' (Depending on the file size, this can take a long time)..."
    echo "- Stage $stage-1: retrieve path information..."
    echo -n "  * Start: "; date
      if [ -e $raw_file ] ; then
        echo  "    File already exists!"
      else
        # Only print lines where the peer is the requested ASN and remove the peer from the AS path
        bgpdump -m $mrt_file | awk -F '|' -v asn=$data_asn '{ if ( $5 == asn ) { print $7 " " } }' | sed -e "s/^$data_asn //g" > $raw_file
      fi
    echo -n "  * Stop: "; date

    echo "- Stage $stage-2: Reduce raw data to unique AS paths..."
    echo -n "  * Start: "; date
      cat $raw_file | sort -u >> $sort_file
    echo -n "  * Stop: "; date
  else
    echo "MRT dump file '$mrt_file' not found!"
  fi
  ((file_num++))
done
((stage++))
echo
echo "Process '$sort_file' file, remove duplicates and clean up..."
echo "- Stage $stage: Sort file '$sort_file'..."
echo -n "  * Start: "; date
  cat $sort_file | sed "/^[ \t]*$/d" | sort -u >> $out_file
echo -n "  * Stop: "; date
((stage++))
echo "- Stage $stage: Cleanup working files..."
echo -n "  * Start: "; date
  if [ $clean_mrt -eq 1 ] ; then
    for mrt_file in ${mrt_files[@]} ; do
      rm $mrt_file
    done
  fi
  if [ $clean_raw -eq 1 ] ; then
    rm $data_asn.*.raw
  fi
  rm $sort_file
echo -n "  * Stop: "; date

path_count=$(wc -l $out_file | awk '{ print $1 }')
echo
echo "$path_count unique AS paths found."

# Calculate processing time.
stop_time=$(date +%s)
total_sec=$(($stop_time-$start_time))
total_hrs=$(($total_sec / 3600)); total_sec=$(($total_sec % 3600))
total_min=$(($total_sec / 60)); 
total_sec=$(($total_sec % 60))
if [ $total_hrs -lt 10 ] ; then total_hrs="0$total_hrs"; fi
if [ $total_min -lt 10 ] ; then total_min="0$total_min"; fi
if [ $total_sec -lt 10 ] ; then total_sec="0$total_sec"; fi
echo
echo "Processing time: ($total_hrs:$total_min:$total_sec)"
echo