/*
secure_control_protocol
IPRange Tests
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/util/ip_range.dart';
import 'package:test/test.dart';

void main() {
  // ====== Test static methods ======

  //Test Octets to Integer conversion
  test('Get integer value of 192.168.2.122', () {
    expect(IPRange.octetsToInteger([192, 168, 2, 122]), equals(3232236154));
  });

  test('Get integer value of 10.226.181.5', () {
    expect(IPRange.octetsToInteger([10, 226, 181, 5]), equals(182629637));
  });

  // Test octet to String conversion
  test('Get String of [10, 0, 0, 1] address', () {
    expect(IPRange.octetsToString([10, 0, 0, 1]), equals('10.0.0.1'));
  });

  test('Get String of 192.168.2.56 address', () {
    expect(IPRange.octetsToString([192, 168, 2, 56]), equals('192.168.2.56'));
  });

  // Test integer to octet conversion
  test('Get octets of 3232236154 address', () {
    expect(IPRange.integerToOctets(3232236154), equals([192, 168, 2, 122]));
  });

  test('Get octets of 182629637 address', () {
    expect(IPRange.integerToOctets(182629637), equals([10, 226, 181, 5]));
  });

  // ====== Test member methods ======

  // Test calculation of last IP address
  test('Get last IP address in 192.168.2.0/24 network', () {
    expect(IPRange('192.168.2.0', 24).calculateLastIpAddress(),
        equals([192, 168, 2, 254]));
  });

  test('Get last IP address in 10.16.0.0/16 network', () {
    expect(IPRange('10.16.0.0', 16).calculateLastIpAddress(),
        equals([10, 16, 255, 254]));
  });

  // Test calculation of network address
  test('Get network address of 10.16.0.10/8 network', () {
    expect(IPRange('10.16.0.0', 16).calculateNetworkAddress(),
        equals([10, 16, 0, 0]));
  });

  test('Get network address of 192.168.2.56/24 network', () {
    expect(IPRange('192.168.2.56', 24).calculateNetworkAddress(),
        equals([192, 168, 2, 0]));
  });

  test('Get network address of 192.168.2.56/16 network', () {
    expect(IPRange('192.168.2.32', 16).calculateNetworkAddress(),
        equals([192, 168, 0, 0]));
  });

  // Test calculation of all IP addresses in range
  test('Get all IP addresses in range 192.168.2.0/30', () {
    expect(IPRange('192.168.2.0', 30).getAllIpAddressesInRange(),
        equals(['192.168.2.1', '192.168.2.2']));
  });

  test('Get all IP addresses in range 10.226.181.0/28', () {
    expect(
        IPRange('10.226.181.0', 28).getAllIpAddressesInRange(),
        equals([
          '10.226.181.1',
          '10.226.181.2',
          '10.226.181.3',
          '10.226.181.4',
          '10.226.181.5',
          '10.226.181.6',
          '10.226.181.7',
          '10.226.181.8',
          '10.226.181.9',
          '10.226.181.10',
          '10.226.181.11',
          '10.226.181.12',
          '10.226.181.13',
          '10.226.181.14'
        ]));
  });
}
