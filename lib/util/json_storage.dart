import 'dart:io';
import 'dart:convert';

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
