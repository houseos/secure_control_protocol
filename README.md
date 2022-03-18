# Secure Control Protocol Client Library written in Dart

This is a client library for IoT devices implementing the [Secure Control Protocol](https://github.com/houseos/SCP). It is used by the [HouseOS Client App](https://github.com/houseos/houseos_client).

It also provides a very basic CLI client for demonstration purposes.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Build and run for development

Install the Dart SDK version > 2.10.

Afterwards run `pub get` to fetch all dependencies.

Now the commands below can be used.

## Build as native application

`dart compile exe ./bin/scp_client.dart`

## Run without build

See below.

## Run Tests

`dart run <path to test>`

## CLI Client

The CLI client supports all necessary commands:

```
> dart .\bin\scp_client.dart help
Secure Control Protocol CLI Client

Usage: scp-client.exe <command> [arguments]

Global options:
-h, --help    Print this usage information.

Available commands:
  control     Control the selected device.
  discover    Discover all devices in a given IP range.
  measure     Measure a value.
  provision   Provision all available devices.
  rename      Rename the selected device.
  reset       Reset the selected device.
  update      Update the stored information of all devices in a given IP range.

Run "scp-client.exe help <command>" for more information about a command.
```

### Control

```
> dart .\bin\scp_client.dart control help
Control the selected device.

Usage: scp-client.exe control [arguments]
-h, --help                                                                     Print this usage information.
-a, --action=<Any string registered in the device.>                            The action to send to the device.
-d, --deviceId=<Can be looked up in the json with the provisioned devices.>    The ID of the device to control.
-j, --json=<Path in the filesystem.>                                           Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

### Discover

```
> dart .\bin\scp_client.dart help discover
Discover all devices in a given IP range.

Usage: scp-client.exe discover [arguments]
-h, --help                                          Print this usage information.
-i, --ipaddress=<IPv4 Address (AAA.BBB.CCC.DDD)>    IP address from the subnet to be scanned.
-m, --mask=<0 - 32>                                 The subnet mask of the network to scan.
-j, --json=<Path in the filesystem.>                Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

### Measure

```
> dart .\bin\scp_client.dart help measure
Measure a value.

Usage: scp-client.exe measure [arguments]
-h, --help                                                                     Print this usage information.
-a, --action=<Any string registered in the device.>                            The measure action to send to the device.
-d, --deviceId=<Can be looked up in the json with the provisioned devices.>    The ID of the device to control.
-j, --json=<Path in the filesystem.>                                           Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

### Provision 

```
> dart .\bin\scp_client.dart help provision
Provision all available devices.

Usage: scp-client.exe provision [arguments]
-h, --help                                          Print this usage information.
-i, --ipaddress=<IPv4 Address (AAA.BBB.CCC.DDD)>    IP address from the subnet to be scanned.
-m, --mask=<0 - 32>                                 The subnet mask of the network to scan.
-s, --ssid=<SSID>                                   The SSID of the Wifi the device should connect to.
-p, --password=<String (max. 32 Characters)>        The Wifi password.
-n, --name=<String (max. 32 Characters)>            The new name of the device.
-j, --json                                          Export the provisioned devices to the given JSON file to be able to load them for the next command.

Run "scp-client.exe help" to see global options.
```

### Rename

```
> dart .\bin\scp_client.dart help rename
Rename the selected device.

Usage: scp-client.exe rename [arguments]
-h, --help                                                                     Print this usage information.
-d, --deviceId=<Can be looked up in the json with the provisioned devices.>    The ID of the device to control.
-n, --name=<>                                                                  The new name of the device.
-j, --json=<Path in the filesystem.>                                           Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

### Reset

```
> dart .\bin\scp_client.dart help reset 
Reset the selected device.

Usage: scp-client.exe reset [arguments]
-h, --help                                                                     Print this usage information.
-d, --deviceId=<Can be looked up in the json with the provisioned devices.>    The ID of the device to control.
-j, --json=<Path in the filesystem.>                                           Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

### Update 

```
> dart .\bin\scp_client.dart help update
Update the stored information of all devices in a given IP range.

Usage: scp-client.exe update [arguments]
-h, --help                                          Print this usage information.
-i, --ipaddress=<IPv4 Address (AAA.BBB.CCC.DDD)>    IP address from the subnet to be scanned.
-m, --mask=<0 - 32>                                 The subnet mask of the network to scan.
-j, --json=<Path in the filesystem.>                Path to the JSON file containing all known devices.

Run "scp-client.exe help" to see global options.
```

## License
SPDX-License-Identifier: GPL-3.0-only

The full version of the license can be found in LICENSE.
