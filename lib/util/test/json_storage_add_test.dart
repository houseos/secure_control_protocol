/*
secure_control_protocol
JsonStorage Add Tests
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/util/json_storage.dart';
import 'package:test/test.dart';
import 'dart:convert';

void main() async {
  // ====== Test static methods ======

  var defaultData = json.decode(
      '{[{"deviceId": "1234567890",            "deviceType": "shutter-control",            "ipAddress": "192.168.2.2",            "isDefaultPasswordSet" : "false",            "knownPassword": "1234567890123456",            "currentPasswordNumber": "1"        },        {            "deviceId": "1234567891",            "deviceType": "shutter-control",            "ipAddress": "192.168.2.2",            "isDefaultPasswordSet" : "false",            "knownPassword": "1234567890123456",            "currentPasswordNumber": "1"        }    ]}'
          .replaceAll(new RegExp(r' '), ''));
  var resultData = json.decode('[{"deviceType":"shutter-control","deviceId":"1234567890","isDefaultPasswordSet":"false","knownPassword":"1234567890123456","currentPasswordNumber":"1"},{"deviceType":"shutter-control","deviceId":"1234567891","isDefaultPasswordSet":"false","knownPassword":"1234567890123456","currentPasswordNumber":"1"},{"deviceType":"shutter-control","deviceId":"0987654321","isDefaultPasswordSet":"false","knownPassword":"1234567890123","currentPasswordNumber":"3"}]');
  String testDataPath = '.\\lib\\util\\test\\devices.json';
  //Test Octets to Integer conversion
  print('Default value:');
  print(defaultData);

  await test('Add device to File', () async {
    await JsonStorage.storeDevice(
        ScpDevice(
          knownPassword: '1234567890123',
          currentPasswordNumber: 3,
          deviceId: '0987654321',
          deviceType: 'shutter-control',
          ipAddress: '192.168.42.42',
          isDefaultPasswordSet: false,
        ),
        testDataPath);
        
    var jsonData = await JsonStorage.readJson(testDataPath);
    expect(jsonData, equals(resultData));
  });
}
