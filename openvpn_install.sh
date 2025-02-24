#!/bin/bash

     
     echo "Enter Number to perform listed task from below options"
     echo " "
     echo "1. Install & configure openvpn"
     echo "2. Create client.ovpn file"
     echo "3. Uninstall openvpn & easyrsa"
     read choice


 case $choice in

 1) 
     ## Check whether openvpn & easyrsa is alreayd installed or not 

    if rpm -q openvpn &> /dev/null && rpm -q easy-rsa &> /dev/null; then

     echo "Openvpn & easy-rsa already installed. If you want to reconfigure it or uninstall then select option no 3"

     exit 1 
  
 else
      echo " openvpn installation started"
  
    # Installing both packages openvpn & eas-rsay
 
     yum install epel-release -y
     yum install openvpn easy-rsa –y

    ## Declared assigned path to variables for copying unknow openvpn folder version name     

     Default_folder=/usr/share/easy-rsa/
     digit=$(ls -v "$Default_folder" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | tail -n 1)
     source_path=$(echo "/usr/share/easy-rsa/$digit/*")
     Destination_path="/etc/openvpn/"
     cp -r $source_path $Destination_path 


   ## 
 
    echo "$(ls -l /etc/openvpn/)"
    cd /etc/openvpn/
   ./easyrsa init-pki
   ./easyrsa build-ca nopass
   ./easyrsa gen-req server nopass
   ./easyrsa sign-req server server
   ./easyrsa gen-dh
    openvpn --genkey --secret ta.key

 ## Moved required certificates & keys to path /etc/openvpn/client/
    
   mv /etc/openvpn/pki/issued/server.crt /etc/openvpn/server.crt
   mv /etc/openvpn/pki/private/server.key /etc/openvpn/server.key
   mv /etc/openvpn/pki/dh.pem /etc/openvpn/dh.pem


 # Configure OpenVPN Server


 # Copied server.conf file from source location to destionation

   cp -rv /usr/share/doc/openvpn*/sample/sample-config-files/server.conf /etc/openvpn/server/server.conf

  
 # Updated existing server.conf file with required configuration lines     
 
  echo " " >> /etc/openvpn/server/server.conf

 # remove lines which starts with ca & enter ca with it's file path

  sed -i '/ca/d' /etc/openvpn/server/server.conf
  echo "ca /etc/openvpn/pki/ca.crt" >> /etc/openvpn/server/server.conf

 # remove lines which starts with cert & enter line "cert /etc/openvpn"
  sed -i '/cert/d' /etc/openvpn/server/server.conf
  echo "cert /etc/openvpn/server.crt" >> /etc/openvpn/server/server.conf

 # remove lines which starts with key & enter line "key /etc/openvpn"
  sed -i '/key/d' /etc/openvpn/server/server.conf
  echo "key /etc/openvpn/server.key" >> /etc/openvpn/server/server.conf

 # remove lines which starts with dh & enter line "dh /etc/openvpn/"
  sed -i '/dh/d' /etc/openvpn/server/server.conf
  echo "dh /etc/openvpn/dh.pem" >> /etc/openvpn/server/server.conf

 # remove lines which starts with tls-auth & enter line tls-aut /etc/openvpn/
  sed -i '/tls-auth/d' /etc/openvpn/server/server.conf
  echo "tls-auth /etc/openvpn/ta.key 0" >> /etc/openvpn/server/server.conf


 # Enable IP forwarding
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.conf
  sysctl -p

   # Configure Firewall 
   firewall-cmd --add-service=openvpn --permanent
   firewall-cmd --add-masquerade --permanent
   firewall-cmd --reload

 # Start & enable openvpn service

   systemctl start openvpn-server@server.service
   systemctl enable openvpn-server@server.service
   systemctl status openvpn-server@server.service



# Set rw permissions to root user only

  #chmod 600 /etc/openvpn/server/server.conf /etc/openvpn/*.key /etc/openvpn/*.crt
  
  echo " "
  echo "## Successfully configured openvpn server ##"

fi
;;


2)

## Check whether openvpn & easyrsa is alreayd installed or not

    if rpm -q openvpn &> /dev/null && rpm -q easy-rsa &> /dev/null; then

# Go to path where easyrsa located
    cd /etc/openvpn/  

# Prompt user to enter name for client or username"
     echo "Enter username or client name"
     read Name
 
 # Set up Easy-RSA for OpenVPN
      cd /etc/openvpn/
     ./easyrsa gen-req "$Name" nopass
     ./easyrsa sign-req client "$Name"

 # Move client certificate & keys to client folder
    mv /etc/openvpn/pki/issued/$Name.crt /etc/openvpn/client/$Name.crt
    mv /etc/openvpn/pki/private/$Name.key /etc/openvpn/client/$Name.key

# Define the variables with their values
   OUTPUT_FILE="$Name.ovpn"
   VPN_SERVER="192.168.0.102"
   VPN_PORT="1194"
   PROTOCOL="udp"
   CA_CERT="/etc/openvpn/pki/ca.crt"
   CLIENT_CERT="/etc/openvpn/client/$Name.crt"
   CLIENT_KEY="/etc/openvpn/client/$Name.key"
   TLS_AUTH="/etc/openvpn/ta.key"

# Check if the required files are available

  if [[ ! -f $CA_CERT || ! -f $CLIENT_CERT || ! -f $CLIENT_KEY || ! -f $TLS_AUTH ]]; then

  echo "Error: Required certificates/keys are missing in the current directory."

  exit 1

fi

# Create the .ovpn configuration file

 cat > $OUTPUT_FILE << EOF
 client
 dev tun
 proto udp
 remote 192.168.0.102 1194
 resolv-retry infinite
 nobind
 persist-key
 persist-tun
 tls-auth /etc/openvpn/ta.key 1
 cipher AES-256-CBC
 verb 3

<ca>
$(awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' $CA_CERT)
</ca>
<cert>
$(awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' $CLIENT_CERT)
</cert>
<key>
$(awk '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/' $CLIENT_KEY)
</key>
<tls-auth>
$(awk '/-----BEGIN OpenVPN Static key V1-----/,/-----END OpenVPN Static key V1-----/' $TLS_AUTH)
</tls-auth>

EOF

  echo "OpenVPN client configuration file '$OUTPUT_FILE' has been generated successfully."
  echo "Location:$(pwd)"
  ls -l "$(pwd)"/$Name.ovpn

else

     echo " Openvpn not installed. Kindly install it & then choose 2 option"

fi
 
;;

3) 

 # Uninstall openvpn,easy-rsa & remove their configuration files
 
  yum remove openvpn easy-rsa -y
  rm -rf /etc/openvpn
  ls -l /etc/openvpn/
  echo " Removed openvpn & easy-rsa"

;;

*)

 echo " Enter correct number for required operation:"

esac
