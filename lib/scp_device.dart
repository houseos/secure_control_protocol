/*
secure_control_protocol
ScpDevice Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class ScpDevice {
  String deviceType;
  String deviceId;
  List<ScpDeviceAction> actions;

  String ipAddress;
  bool isDefaultPasswordSet;
  String knownPassword;
  int currentPasswordNumber;

  ScpDevice(
      {this.deviceId,
      this.deviceType,
      this.ipAddress,
      this.isDefaultPasswordSet,
      this.knownPassword,
      this.currentPasswordNumber}) {
    this.actions = List<ScpDeviceAction>.empty(growable: true);
    if (this.deviceType == ScpDeviceTypes.SHUTTER_CONTROL) {
      this.actions.add(ScpDeviceAction(name: 'Open', action: 'up'));
      this.actions.add(ScpDeviceAction(name: 'Close', action: 'down'));
      this.actions.add(ScpDeviceAction(name: 'Stop', action: 'stop'));
    }
  }

  static List<ScpDevice> devicesfromJson(var json) {
    List<ScpDevice> devices = List<ScpDevice>.empty(growable: true);
    for (var j in json) {
      ScpDevice d = ScpDevice(
        deviceId: j['deviceId'],
        deviceType: j['deviceType'],
        ipAddress: j['ipAddress'],
        isDefaultPasswordSet:
            j['isDefaultPasswordSet'] == 'false' ? false : true,
        knownPassword: j['knownPassword'],
        currentPasswordNumber: int.parse(j['currentPasswordNumber']),
      );
      devices.add(d);
    }
    return devices;
  }

  @override
  String toString() {
    return "ScpDevice:\n Type: $deviceType,\n ID: $deviceId,\n IP: $ipAddress,\n default password: $isDefaultPasswordSet\n password: $knownPassword,\n current password number: $currentPasswordNumber";
  }

  Map<String, dynamic> toJson() => {
        'deviceType': deviceType,
        'deviceId': deviceId,
        'ipAddress': ipAddress,
        'isDefaultPasswordSet': '$isDefaultPasswordSet',
        'knownPassword': knownPassword,
        'currentPasswordNumber': '$currentPasswordNumber',
      };
}

class ScpDeviceTypes {
  static final String SHUTTER_CONTROL = "shutter-control";
}

class ScpDeviceAction {
  final String name;
  final String action;

  ScpDeviceAction({this.name, this.action});
}
