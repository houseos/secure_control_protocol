/*
secure_control_protocol
IPRange Util Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:math';

class IPRange {
  int netmask;

  int address = 0;

  IPRange(String networkAddress, int netmask) {
    List<int> octets = getOctetsOfIpAddress(networkAddress);
    this.address = octetsToInteger(octets);

    this.netmask = netmask;
  }

  List<int> getOctetsOfIpAddress(String ipAddress) {
    List<int> octets = new List();
    ipAddress.split('.').forEach((octet) => octets.add(int.parse(octet)));
    return octets;
  }

  static int octetsToInteger(List<int> octets) {
    int address = 0;
    address += (octets[0] << 24);
    address += (octets[1] << 16);
    address += (octets[2] << 8);
    address += (octets[3]);
    return address;
  }

  static List<int> integerToOctets(int address) {
    List<int> octets = new List(4);
    octets[0] = (address & (255 << 24)) >> 24;
    octets[1] = (address & (255 << 16)) >> 16;
    octets[2] = (address & (255 << 8)) >> 8;
    octets[3] = address & (255);
    return octets;
  }

  static String octetsToString(List<int> octets) {
    return '${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}';
  }

  List<int> calculateLastIpAddress() {
    List<int> octets = new List(4);

    // Determine host bits
    int hostbits = 32 - netmask;
    // Set all host bits to 1
    int invertor = 0;
    for (int i = 0; i < hostbits; i++) {
      invertor += pow(2, i);
    }
    int lastAddress = address | invertor;
    //substract 1 to get last address instead of broadcast address
    lastAddress--;

    octets[0] = (lastAddress & (255 << 24)) >> 24;
    octets[1] = (lastAddress & (255 << 16)) >> 16;
    octets[2] = (lastAddress & (255 << 8)) >> 8;
    octets[3] = lastAddress & (255);
    return octets;
  }

  List<int> calculateNetworkAddress() {
    List<int> octets = new List(4);

    // Get only the network bits set to 1
    int invertor = 0;
    for (int i = 0; i < netmask; i++) {
      invertor += pow(2, 31 - i);
    }
    int lastAddress = address & invertor;

    octets[0] = (lastAddress & (255 << 24)) >> 24;
    octets[1] = (lastAddress & (255 << 16)) >> 16;
    octets[2] = (lastAddress & (255 << 8)) >> 8;
    octets[3] = lastAddress & (255);
    return octets;
  }

  List<String> getAllIpAddressesInRange() {
    List<String> ipAddresses = new List<String>();

    //start with lowest address
    int currentAddress = octetsToInteger(this.calculateNetworkAddress());
    //increment address using int value
    while (currentAddress < octetsToInteger(this.calculateLastIpAddress())) {
      currentAddress++;
      ipAddresses.add(octetsToString(integerToOctets(currentAddress)));
    }
    // generate the string representation and store it in list
    return ipAddresses;
  }

  void printBitmask(int address) {
    print('Bitmask: ${address.toRadixString(2)}');
  }
}
