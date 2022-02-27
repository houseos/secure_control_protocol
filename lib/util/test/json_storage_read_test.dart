/*
secure_control_protocol
JsonStorage Read Tests
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/util/json_storage.dart';
import 'package:test/test.dart';
import 'dart:convert';

void main() async {
  // ====== Test static methods ======

  var defaultData = json.decode(
      '{"devices":[{"deviceId": "1234567890",            "deviceType": "shutter-control",            "ipAddress": "192.168.2.2",            "isDefaultPasswordSet" : "false",            "knownPassword": "1234567890123456",            "currentPasswordNumber": "1"        },        {            "deviceId": "1234567891",            "deviceType": "shutter-control",            "ipAddress": "192.168.2.2",            "isDefaultPasswordSet" : "false",            "knownPassword": "1234567890123456",            "currentPasswordNumber": "1"        }    ]}'
          .replaceAll(new RegExp(r' '), ''));
  String testDataPath = '.\\lib\\util\\test\\devices.json';
  //Test Octets to Integer conversion
  print('Default value:');
  print(defaultData);
  test('Read JSON String from File', () async {
    var jsonData = await JsonStorage.readJson(testDataPath);
    expect(jsonData, equals(defaultData));
  });
}
