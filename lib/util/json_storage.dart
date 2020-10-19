/*
secure_control_protocol
JsonStorage Util Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// Standard Library
import 'dart:io';
import 'dart:convert';

// SCP
import 'package:secure_control_protocol/scp_device.dart';

class JsonStorage {
  static void storeDevice(ScpDevice device, String path) async {
    //read file
    var jsonData = await JsonStorage.readJson('$path');
    List<ScpDevice> devices = List<ScpDevice>();
    if (jsonData != null) {
      devices.addAll(ScpDevice.devicesfromJson(jsonData));
    } else {
      print('File $path does not exist, creating it...');
    }
    //add to List, remove if it already exists to mitigate duplicates
    devices.removeWhere((element) => element.deviceId == device.deviceId);
    devices.add(device);
    //write List to JSON
    String encoded = jsonEncode(devices);
    final file = await File('$path');
    // Write the file
    file.writeAsString('$encoded', mode: FileMode.write);
  }

  static void updateFromJson(String newJson, String path) async{
    final file = await File('$path');
    // Write the file
    file.writeAsString('$newJson', mode: FileMode.write);
  }

  static Future readJson(String path) async {
    if (await File('$path').exists()) {
      final file = await File('$path');
      String content = await file.readAsString();
      var jsonString = json.decode(content);
      return jsonString;
    }
    print('File $path does not exist.');
    return null;
  }
}
