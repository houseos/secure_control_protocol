class ScpDevice {
  String deviceType;
  String deviceId;

  String ipAddress;
  bool defaultPassword;
  String knownPassword;
  int currentPasswordNumber;

  ScpDevice(
      {this.deviceId,
      this.deviceType,
      this.ipAddress,
      this.defaultPassword,
      this.knownPassword,
      this.currentPasswordNumber});

  void sendControlUp() {}

  void sendControlDown() {}

  void sendControlStop() {}
}
