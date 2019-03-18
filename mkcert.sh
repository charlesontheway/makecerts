#!/bin/bash
#Create SSL certificate rootCA file, rootCA.bks file,pks12 file,...
#Updated: 2017-06-12
#Neo: 474183554@qq.com

#Before run this script, please make sure that certgen_required.tar.gz
#in the current dir, where this script located

# Usage: `basename $0` [-a signature_algorithm] [-D working_directory] [-m] [-n CN_IP] [-p ssl_port] [-h]
#  -a  Specify the signature algorithm, sha1 or sha256, default is sha1
#  -D  Specify a working directory, default is /var/ssl/
#  -m  Specify SAN ip addresses which used by configuration file manually
#      if -m option is specified, you will be asked for subjectAltName IP address later
#  -n  Specify Common Name(CN) ip addresses  manually
#  -p  Specify https server port, default is 1443
#  -h  Display this help message

show_usage()
{
        echo "Usage: `basename $0` [-a signature_algorithm] [-D working_directory] [-m] [-n CN_IP] [-p ssl_port] [-h]"
        echo "  -a  Specify the signature algorithm, sha1 or sha256, default is sha1"
        echo "  -D  Specify a working directory, default is /var/ssl"
	echo "  -m  Specify SAN ip addresses which used by configuration file manually"
	echo "      if -m option is specified, you will be asked for subjectAltName IP address later"
	echo "  -n  Specify Common Name(CN) ip addresses  manually"
	echo "  -p  Specify https server port, default is 1443"
        echo "  -h  Display this help message"
        echo "Before run this script, please make sure that certgen_required.tar.gz"
        echo "in the current dir, which this script located"
        exit 126
}

#Generate a random password
random_password(){

	MATRIX="ABCDEFGHIJKLMNOPQRSTUVWXYZ9876543210abcdefghijklmnopqrstuvwxyz"
	LENGTH="9"
	while [ "${n:=1}" -le "$LENGTH" ]
	do
		PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
		let n+=1
	done
	echo $PASS
}

[ $# -lt 1 ] && show_usage

# Source the bash profile
if [ -f ~/.bash_profile ]; then
                . ~/.bash_profile
fi

# Source the function library
. /etc/init.d/functions

ECHO_STYLE_RED="\\033[31m"
ECHO_STYLE_GREEN="\\033[32m"
ECHO_STYLE_YELLOW="\\033[33m"
ECHO_STYLE_BLUE="\\033[34m"
ECHO_STYLE_PURPLE="\\034[35m"
ECHO_STYLE_CYAN="\\033[36m"
ECHO_STYLE_END="\\033[0m"


required_file=./certgen_required.tar.gz
workdir=/var/ssl
signature="sha1"
sign_ok=1
user="videouser"
serverport="1443"
asksan=0
cn=0

# Get the option args
while getopts :mn:a:D:p: OPTION
do
        case $OPTION in
                a)signature=$OPTARG;;
                D)workdir=$OPTARG;;
		p)serverport=$OPTARG;;
                m)asksan=1;;
                n)cn=$OPTARG;;
                ?)show_usage
        esac
done

#shift the args which have already been read
shift "$((OPTIND-1))"

#if there are unwanted args ,then show help message
[ ! -z "$@" ] && show_usage

#Check the validity of parameters
case $signature in
	sha1|sha256)sign_ok=1;;
	*)sign_ok=0;;
esac

if [ $sign_ok == 0 ]; then
	echo -e "${ECHO_STYLE_RED}$signature is a Invalid signature algorithm, the valid value is 'sha1' or 'sha256'${ECHO_STYLE_END}"
	exit 1
fi

to_continue=0
if [ ! -d $workdir ]; then
	echo "$workdir does not exist! now creating..."
	mkdir -p $workdir
        to_continue=1
	echo "$workdir has been created."
else
        echo -n -e "${ECHO_STYLE_CYAN}Warning: All contents in $workdir would be removed! Continue?[Yes/No]${ECHO_STYLE_END}"
	read answer
        case $answer in
                Y|y)to_continue=1;;
                Yes|yes)to_continue=1;;
                N|n)to_continue=0;;
                No|no)to_continue=0;;
                *)to_continue=-1;;
        esac

fi

#Determine continue or not
if [ ! $to_continue == 1 ]; then
	echo "Abort by user!"
	exit 2
fi

#get the host IP Address via default route
if [ $cn == 0 ]; then
	devname=`ip route show|sed -n '/^default/p'|awk '{print $5}'`
	serverip=`ifconfig|grep -A2 $devname |grep inet|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
else 
	serverip="$cn"
fi

#Test to see if we get a valid ip address
echo $serverip | grep -q -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
if [ $? != 0 ]; then
	echo -e "${ECHO_STYLE_RED}Error! Can not get a valid IP Address for Common Name.${ECHO_STYLE_END}"
	exit 17
fi

#get ip addresses for subjectAltName, which will be used in [ v3_ca ] and [ alternate_names ] section
arr_devname=(`ip address show|sed -n -r '/^[0-9]{1,3}:/p'|awk -F: '{print $2}'|sed 's/^[[:blank:]]*//'|grep -v lo`)
if [ ${#arr_devname[@]} -ge 1 ]; then
#The following ip addressess will be used as subjectAltName(SAN)
#However, -m option can override these ip addressess
	k=0
	for i in `seq 0 $((${#arr_devname[@]}-1))`; do
#		echo -n "${arr_devname[$i]} : "
		tmp_ip=`ifconfig|grep -A2 ${arr_devname[$i]}|grep inet|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
		echo ${tmp_ip}|grep -q -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
		if [ $? == 0 ]; then
			arr_ip[$k]=${tmp_ip}
			let k+=1
		fi
#		echo  ${arr_ip[$k]}
	done
fi

#Read SAN ip address from keyboard
if [ "$asksan" == 1 ]; then
	okip=0
	echo -n -e "${ECHO_STYLE_CYAN}Please input IP addresses will be used as subjectAltName(SAN):${ECHO_STYLE_END}"
	while :
	do
		read -a arr_ip
		for ij in ${arr_ip[@]}; do
			echo $ij | grep -q -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
			if [ $? != 0 ]; then
				echo -e "${ECHO_STYLE_RED}Bad IP address,input again:${ECHO_STYLE_END}"
				okip=0
				break
			else
				okip=1
			fi
		done
		[ $okip == 1 ] && break
	done	
fi

#Mdify this if necessary
client_subj_prefix="/C=CN/ST=HN/L=CS/O=HNFOO/OU=UNICOMVC/CN=unicomvc."

client_subj_suffix="@hnfoo.com"
client_subj="${client_subj_prefix}${user}${client_subj_suffix}"
#client_subj="/C=CN/ST=HN/L=CS/O=Hnfoo.com/OU=XT/CN=xt.${user}@hnfoo.com"

#Mdify this if necessary
server_subj="/C=CN/L=Changsha/O=hnfoo/CN=${serverip}"

#Mdify this if necessary
ca_subj_prefix="/C=CN/L=Changsha/O=hnfoo"
ca_subj_space=" "
ca_subj_suffix="CA/CN=${serverip}"
ca_subj="${ca_subj_prefix}${ca_subj_space}${ca_subj_suffix}"
#ca_subj='/C=CN/L=Changsha/O=hnfoo CA/CN=127.0.0.1'

bkspasswd=`random_password`
pks12passwd1=`random_password`
pks12passwd2=$(random_password)

echo -e "${ECHO_STYLE_GREEN}Signature algorithm: $signature${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}Workdir is:	$workdir${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}Subject string of client pks12 certificate: $client_subj${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}Subject string of CSR file for the server: $server_subj${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}Subject string of CA self-signed certificate: $ca_subj${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}bks password is:	$bkspasswd${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}pks12 password for ss0001 is:	$pks12passwd1${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}pks12 password for ss0002 is:	$pks12passwd2${ECHO_STYLE_END}"
echo -e "${ECHO_STYLE_GREEN}SubjectAltName(SAN) IP addresses: ${arr_ip[@]}${ECHO_STYLE_END}"
echo -n -e "${ECHO_STYLE_CYAN}All information are collected, please confirm, Is that right?[Yes/No]${ECHO_STYLE_END}"
read confirm

#Determine continue or not
to_continue=0
case $confirm in
        Y|y)to_continue=1;;
        Yes|yes)to_continue=1;;
        N|n)to_continue=0;;
        No|no)to_continue=0;;
        *)to_continue=-1;;
esac

if [ ! $to_continue == "1" ]; then
	echo "Abort!"
	exit 3
fi

#Test and extract the required dir and files
if [ ! -f $required_file ]; then
	echo -e "${ECHO_STYLE_RED}Error:	$required_file not found!${ECHO_STYLE_END}"
	exit 124
fi

#Clear all contents in the working directory before extracting required_file
\rm -Rf ${workdir}/*
tar -xzf $required_file -C $workdir 1>/dev/null 2>&1

if [ $? != 0 ]; then
	echo "Extract required_file failed."
	exit 6
fi

cd $workdir

[ -e bcprov-jdk15on-1.46.jar ] || (echo "bcprov-jdk15on-1.46.jar does not exist"; exit 44)
[ $? == 44 ] && exit 8
[ -e openssl-sha1.cnf ] || (echo "openssl-sha1.cnf does not exist"; exit 44)
[ $? == 44 ] && exit 8
[ -e openssl-sha256.cnf ] || (echo "openssl-sha256.cnf does not exist"; exit 44)
[ $? == 44 ] && exit 8
[ -e genClient-sha256.sh ] || (echo "genClient-sha256.sh does not exist"; exit 44)
[ $? == 44 ] && exit 8
[ -e genClient-sha1.sh ] || (echo "genClient-sha1.sh does not exist"; exit 44)
[ $? == 44 ] && exit 8

echo 00 > serial
echo 00 > crlnumber
touch index.txt

#openssl installed?
which openssl 1>/dev/null 2>&1 || (echo "openssl does not exist"; exit 44) 
[ $? == 44 ] && exit 9

# Create CA private key
openssl genrsa -des3 -passout pass:netechXYZ -out  private/rootCA.key 2048
[ ! $? == 0 ] && echo "Create CA private key error." && exit 111

# Remove passphrase
openssl rsa -passin pass:netechXYZ -in private/rootCA.key -out private/rootCA.key
[ ! $? == 0 ] && echo "Remove passphrase error." && exit 112

#Determine which openssl.cnf file to use
if [ $signature == "sha256" ]; then
	\cp -f openssl-sha256.cnf openssl.cnf
elif [ $signature == "sha1" ]; then
	\cp -f openssl-sha1.cnf openssl.cnf
else
	echo "Invalid signature algorithm"
	exit 4
fi
[ ! $? == 0 ] && echo "Error occurred while copy openssl.cnf " && exit 113

#Replace the ssl working dir in openssl.cnf
############Old code of sed operation
#pattern_str1="dir"
#pattern_str2="Where everything is kept"

#sed -i "s/^$pattern_str1.*$pattern_str2/#&/" openssl.cnf
#sed -i "/^#$pattern_str1.*$pattern_str2/a\dir = $replaced_str" openssl.cnf
#the following command do the same things
#sed -i 's/^'"$pattern_str1"'.*'"$pattern_str2"'/#&/' openssl.cnf
#sed -i '/^#'"$pattern_str1"'.*'"$pattern_str2"'/a\dir = '"$replaced_str" openssl.cnf

###########Optimized code of sed operation
section="CA_default"
valname="dir"
replaced_str="`pwd`"
sed -i "/^[ \t]*\[[ \t]*$section[ \t]*\]/,/^[ \t]*\[/ {s/^[ \t]*$valname[ \t]*=/#&/}" openssl.cnf
linenum=`sed -n "/^[ \t]*\[[ \t]*$section[ \t]*\]/,/^[ \t]*\[/ {/^#[ \t]*$valname[ \t]*=/=}" openssl.cnf`
sed -i "$linenum a\dir = $replaced_str" openssl.cnf
###########In a interactive shell, the following one line command can do all the things above, 
###########but it does NOT work in a script file
#sed -i '/^[ \t]*\[[ \t]*'"$section"'[ \t]*\]/,/^[ \t]*\[/s/^[ \t]*'"$valname"'[ \t]*=/& '"$replaced_str"' #/' openssl.cnf

section="v3_ca"
valname="subjectAltName"

if [ "${#arr_ip[@]}" == 0 ]; then
	echo -e "${ECHO_STYLE_RED}Error: Can not determine subjectAltName IP address!${ECHO_STYLE_END}"
	exit 18
else
	san_ip=""
	for j in "${arr_ip[@]}"; do
		san_ip="${san_ip} IP:$j,"
	done
fi
replaced_str=`echo $san_ip|sed 's/,$//'`
linenum=`sed -n "/^[ \t]*\[[ \t]*$section[ \t]*\]/,/^[ \t]*\[/ {/^[ \t]*$valname[ \t]*=/=}" openssl.cnf`
sed -i "$linenum d" openssl.cnf
sed -i "$linenum i$valname         = $replaced_str" openssl.cnf

section="alternate_names"
valname="IP"
linenum=`sed -n "/^[ \t]*\[[ \t]*$section[ \t]*\]/,/^[ \t]*\[/ {/^[ \t]*$valname\.1[ \t]*=/=}" openssl.cnf`
sed -i "/^[ \t]*\[[ \t]*$section[ \t]*\]/,/^[ \t]*\[/ {/^[ \t]*$valname\.[0-9]\{1,2\}[ \t]*=/d}" openssl.cnf

for i in `seq 0 $((${#arr_ip[@]}-1))`; do
#for ((i=0; i<${#arr_ip[@]}; i++)); do
	sed -i "$((linenum+i)) iIP.$((i+1)) = ${arr_ip[$i]}" openssl.cnf
done

# Create CA self-signed certificate

if [ $signature == "sha256" ]; then
	openssl req -config openssl.cnf -new -sha256 -x509 -subj "$ca_subj" -days 3650 -key private/rootCA.key -out certs/rootCA.crt
elif [ $signature == "sha1" ]; then
	openssl req -config openssl.cnf -new -x509 -subj "$ca_subj" -days 3650 -key private/rootCA.key -out certs/rootCA.crt
else
	echo "Invalid signature algorithm"
	exit 4
fi
[ ! $? == 0 ] && echo "Error occurred while Create CA self-signed certificate." && exit 114
	
which keytool 1>/dev/null 2>&1 || (echo "Java keytool does not exist"; exit 44)
[ $? == 44 ] && exit 115

# generate BKS CA for android
keytool -importcert -v -trustcacerts -file "./certs/rootCA.crt" -alias rootCA -keystore "./certs/rootca.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "./bcprov-jdk15on-1.46.jar" -storetype BKS -storepass $bkspasswd

if [ $? != 0 ]; then
	echo "Bad keytool command args or .jar file error!"
	exit 5
fi

# Create private key for the server 
openssl genrsa -des3 -passout pass:netechXYZ -out private/server.key 2048
[ ! $? == 0 ] && echo "Error occurred while Create private key for the server." && exit 116

# Remove passphrase 
openssl rsa -passin pass:netechXYZ -in private/server.key -out private/server.key
[ ! $? == 0 ] && echo "Error occurred while Remove passphrase." && exit 117

# Create CSR for the server server
if [ $signature == "sha256" ]; then
	openssl req -config openssl.cnf -new -sha256 -subj "$server_subj" -key private/server.key -out csr/server.csr
elif [ $signature == "sha1" ]; then
	openssl req -config openssl.cnf -new -subj "$server_subj" -key private/server.key -out csr/server.csr
else
	echo "Invalid signature algorithm"
	exit 8
fi
[ ! $? == 0 ] && echo "Error occurred while Create CSR for the server." && exit 118

# Create certificate for the server server
openssl ca -batch -config openssl.cnf -days 3650 -extensions v3_req -in csr/server.csr -out certs/server.crt -keyfile private/rootCA.key -cert certs/rootCA.crt -policy policy_anything
[ ! $? == 0 ] && echo "Error occurred while Create certificate for the server" && exit 119

#generate client certificate by calling genClient script
if [ $signature == "sha256" ]; then
	\cp -f genClient-sha256.sh genClient.sh
elif [ $signature == "sha1" ]; then
	\cp -f genClient-sha1.sh genClient.sh
else
	echo "Invalid signature algorithm"
	exit 4
fi
[ ! $? == 0 ] && echo "Error occurred while generate client certificate." && exit 120

	user="videouser"
	client_subj="${client_subj_prefix}${user}${client_subj_suffix}"
	./genClient.sh $user videoUser  "$client_subj"

	user="ss0001"
	client_subj="${client_subj_prefix}${user}${client_subj_suffix}"
	./genClient.sh $user $pks12passwd1 "$client_subj"

	user="ss0002"
	client_subj="${client_subj_prefix}${user}${client_subj_suffix}"
	./genClient.sh $user $pks12passwd2 "$client_subj"

create_readme(){
	readme_file="certs/README.txt"
	[ -f "$readme_file" ] && \rm -f "$readme_file"
	touch "$readme_file"
	echo "#Please use the correct cert file and password for Web user or Android app" >> "$readme_file"
	echo "" >> "$readme_file"
	echo "#Server" >> "$readme_file"
	echo "https://$serverip:$serverport" >> "$readme_file"
	echo "" >> "$readme_file"
	echo "#For App dev:" >> "$readme_file"
	echo "rootCA.crt" >> "$readme_file"
	echo "rootca.bks       <--- (password:	$bkspasswd)" >> "$readme_file"
	echo "clientss0001.p12 <--- (password:	$pks12passwd1)" >> "$readme_file"
	echo "" >> "$readme_file"
	echo "#For Web user:" >> "$readme_file"
	echo "rootCA.crt" >> "$readme_file"
	echo "clientss0002.p12 <--- (password:	$pks12passwd2)" >> "$readme_file"
#convert unix file format to dos style
	sed -i 's/$/\r/' $readme_file
}

create_readme
echo -e "${ECHO_STYLE_GREEN}All certificates are created successfully, Please locate README.txt file at path ${workdir}/certs${ECHO_STYLE_END}"

exit 0
