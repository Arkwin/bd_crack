#!/bin/bash
# set -e # Exit immediately if a command exits with a non-zero status.
# Cracking helper for breachdirectory.org
# Usage: ./bd_crack.sh <email> <optional charset>
#
# This version queries the breachdirectory API for the given email,
# extracts the sha1 and password prefix (before any asterisks),
# and runs hashcat for each result.
#
# Requires: curl, jq, hashcat

if [ -z "$1" ]; then # check to make sure email is present
    echo -e "Mandatory argument missing!\nPlease see README for more details\nUsage:\n\tbd_crack.sh <email> <optional charset>\nexiting"
    exit 1
fi

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "jq is required but not installed. Please install jq."
    exit 1
fi

email="$1"
charset_formatted=""

if [ -n "$2" ]; then # if charset is specified
    charset="$2"
    valid_charsets="ludhHsb"
    if [[ "$charset" =~ ^["$valid_charsets"]+$ ]]; then
        charset=$(grep -o . <<< "$charset" | sort -u | tr -d '\n')
        for (( i=0; i<${#charset}; i++ )); do
            if [ $i -eq 0 ]; then
                charset_formatted+="?"
            fi
            charset_formatted+="${charset:$i:1}"
            if [ $i -lt $((${#charset}-1)) ]; then
                charset_formatted+="?"
            fi
        done
    else
        echo -e "INVALID CHARSET, DEFAULTING TO DEFAULT CHARSET"
        charset_formatted="?l?u?d?s"
    fi
else
    charset_formatted="?l?u?d?s"
fi

# API credentials
API_HOST="breachdirectory.p.rapidapi.com"
API_KEY="XXXXXXXXXXXXXXXXXXXXX"
API_URL="https://breachdirectory.p.rapidapi.com/?func=auto&term=$email"

# Query the API
response=$(curl -sL -w "\n%{http_code}" --request GET \
    --url "$API_URL" \
    --header "x-rapidapi-host: $API_HOST" \
    --header "x-rapidapi-key: $API_KEY")

# Split response and status code
http_body=$(echo "$response" | sed '$d')
http_code=$(echo "$response" | tail -n1)

success=$(echo "$http_body" | jq -r '.success' 2>/dev/null)
if [ "$success" != "true" ]; then
    echo "API call failed or no results found."
    echo "HTTP status code: $http_code"
    echo "Raw response: $http_body"
    exit 1
fi

found=$(echo "$http_body" | jq -r '.found')
if [ "$found" -eq 0 ]; then
    echo "No results found for $email."
    exit 1
fi

results=$(echo "$http_body" | jq -c '.result[]')

count=0
# Use a string to track processed pairs (portable for all bash versions)
seen_pairs=""
while IFS= read -r entry; do
    sha1=$(echo "$entry" | jq -r '.sha1')
    password=$(echo "$entry" | jq -r '.password')
    # Remove asterisks and get prefix before first asterisk
    prefix=$(echo "$password" | sed 's/\*.*//')
    if [ -z "$sha1" ] || [ -z "$prefix" ]; then
        continue
    fi
    if [ ${#prefix} -lt 1 ]; then
        continue
    fi
    # Use up to 5 chars of prefix (if available)
    known5=$(echo "$prefix" | cut -c1-5)
    if [ ${#known5} -ne 5 ]; then
        continue
    fi
    pair_key="${sha1}_${known5}"
    if echo "$seen_pairs" | grep -q "|$pair_key|"; then
        echo "Skipping duplicate pair: sha1=$sha1, prefix=$known5"
        continue
    fi
    seen_pairs+="|$pair_key|"
    outfile="${known5}-${sha1}-$(date +"%d-%m-%Y-%H%M")-cracked.txt"
    echo "Running hashcat for sha1: $sha1, prefix: $known5"
    hashcat -a3 -m100 "$sha1" -1 "$charset_formatted" "$known5?1?1?1?1?1?1?1?1" --increment --increment-min=5 -O -o "$outfile"
    retcode=$?
    if [ $retcode -eq 0 ]; then
        if [ -f "$outfile" ]; then
            echo -e "\nCracked! Result:\n\t$(cat "$outfile")\n"
            echo "Cracked Successfully! Password will be in ./${outfile}!"
        else
            echo "Stopped or Ended! Password not found within the specified mask/charset. Hashcat completed without errors."
            echo "Output file '$outfile' was not created because no crack was found."
        fi
    else
        echo "Hashcat encountered an error or was stopped unexpectedly (exit code: $retcode)."
        echo "Please review hashcat's output above for details."
    fi
    count=$((count+1))
done <<< "$results"

if [ $count -eq 0 ]; then
    echo "No valid results with a 5-character prefix found for $email."
    exit 1
fi
