Secure Control Protocol Client Library written in Dart

To only discovers devices:

`dart ./bin/scp_client discover -i <IP address from the to be scanned subnet> -m <Subnet Mask in Prefix notation>`

To discover devices and afterwards provision them:

`dart ./bin/scp_client provision -i <IP address from the to be scanned subnet> -m <Subnet Mask in Prefix notation> -s <SSID of target Wifi> -p <Password of target Wifi> -j`

| Parameter | Description                                                         |
| --------- | ------------------------------------------------------------------- |
| i         | IP address from the to be scanned subnet                            |
| m         | Subnet Mask in Prefix notation                                      |
| s         | SSID of target Wifi                                                 |
| p         | Password of target Wifi                                             |
| j         | Create JSON file containing all provisioned devices for further use |