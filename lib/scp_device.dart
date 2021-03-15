/*
secure_control_protocol
ScpDevice Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

import 'package:secure_control_protocol/scp_responses/scp_response_discover.dart';
import 'package:secure_control_protocol/util/utils.dart';

class ScpDevice {
  String deviceType;
  String deviceId;
  String deviceName;
  List<String> controlActions;
  List<String> measureActions;

  String ipAddress;
  bool isDefaultPasswordSet;
  String knownPassword;
  int currentPasswordNumber;

  ScpDevice({
    this.deviceId = '',
    this.deviceType = '',
    this.deviceName = '',
    this.ipAddress = '',
    this.isDefaultPasswordSet = false,
    this.knownPassword = '',
    this.currentPasswordNumber = 0,
    this.controlActions = const[],
    this.measureActions = const[],
  });

  static List<ScpDevice> devicesfromJson(var json) {
    List<ScpDevice> devices = List<ScpDevice>.empty(growable: true);
    for (var j in json) {
      devices.add(
        ScpDevice(
          deviceId: j['deviceId'],
          deviceType: j['deviceType'],
          deviceName: j['deviceName'] != null ? j['deviceName'] : '',
          ipAddress: j['ipAddress'],
          isDefaultPasswordSet:
              j['isDefaultPasswordSet'] == 'false' ? false : true,
          knownPassword: j['knownPassword'],
          currentPasswordNumber: int.parse(j['currentPasswordNumber']),
          controlActions: j['controlActions'] != null
              ? Utils.dynamicListToStringList(j['controlActions'])
              : List<String>.empty(),
          measureActions: j['measureActions'] != null
              ? Utils.dynamicListToStringList(j['measureActions'])
              : List<String>.empty(),
        ),
      );
    }
    return devices;
  }

  void updateFromDiscoverResponse(ScpResponseDiscover responseDiscover) {
    this.deviceType = responseDiscover.getDeviceType();
    this.deviceId = responseDiscover.getDeviceId();
    this.deviceName = responseDiscover.getDeviceName();
    this.controlActions = responseDiscover.getControlActions();
    this.measureActions = responseDiscover.getMeasureActions();
    this.currentPasswordNumber = responseDiscover.getCurrentPasswordNumber();
  }

  @override
  String toString() {
    String controlActions = this.controlActions.toString();
    String measureActions = this.measureActions.toString();
    return "ScpDevice:\n Type: $deviceType,\n ID: $deviceId,\n Name: $deviceName,\n IP: $ipAddress,\n default password: $isDefaultPasswordSet\n password: $knownPassword,\n current password number: $currentPasswordNumber,\n controlActions: $controlActions,\n measureActions: $measureActions";
  }

  Map<String, dynamic> toJson() => {
        'deviceType': deviceType,
        'deviceId': deviceId,
        'deviceName': deviceName,
        'ipAddress': ipAddress,
        'isDefaultPasswordSet': '$isDefaultPasswordSet',
        'knownPassword': knownPassword,
        'currentPasswordNumber': '$currentPasswordNumber',
        'controlActions': controlActions,
        'measureActions': measureActions,
      };
}
