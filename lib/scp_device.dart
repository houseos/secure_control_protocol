import 'dart:io';

class ScpDevice {
  String deviceType;
  String deviceId;

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
      this.currentPasswordNumber});

  @override
  String toString(){
    return "ScpDevice:\n Type: $deviceType,\n ID: $deviceId,\n IP: $ipAddress,\n default password: $isDefaultPasswordSet\n password: $knownPassword,\n current password number: $currentPasswordNumber";
  }
}
