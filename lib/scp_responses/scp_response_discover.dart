/*
secure_control_protocol
ScpResponseDiscover Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

// SCP
import 'package:secure_control_protocol/scp.dart';
import 'package:secure_control_protocol/scp_crypto.dart';
import 'package:secure_control_protocol/scp_device.dart';
import 'package:secure_control_protocol/scp_responses/ivalidatable.dart';
import 'package:secure_control_protocol/util/utils.dart';

class ScpResponseDiscover implements IValidatable {
  static const String type = "discover-response";
  String _deviceId = '';
  String _deviceType = '';
  String _deviceName = '';
  int _currentPasswordNumber = 0;
  String _hmac = '';
  List<String> _controlActions = const [];
  List<String> _measureActions = const [];

  ScpResponseDiscover(
      {String deviceId = '',
      String deviceType = '',
      String deviceName = '',
      int currentPasswordNumber = 0,
      String hmac = '',
      List<String> controlActions = const [],
      List<String> measureActions = const []}) {
    _deviceId = deviceId;
    _deviceType = deviceType;
    _deviceName = deviceName;
    _currentPasswordNumber = currentPasswordNumber;
    _hmac = hmac;
    _controlActions = controlActions;
    _measureActions = measureActions;
  }

  /// Returns a ScpResponseDiscover if HMAC valid, otherwise null
  static  Future<ScpResponseDiscover> fromJson(
      var json, List<ScpDevice> devices, bool verifyHmac) async {
    Scp.getInstance().log('$json');
    if (json['type'] == type) {
      if (json['deviceId'] == null ||
          json['deviceId'] == '' ||
          json['deviceType'] == null ||
          json['deviceType'] == '' ||
          json['currentPasswordNumber'] == null ||
          json['currentPasswordNumber'] == '' ||
          json['hmac'] == null ||
          json['hmac'] == '') {
            print('discover response invalid');
        return ScpResponseDiscover();
      }

      ScpResponseDiscover discoverResponse = ScpResponseDiscover(
        deviceId: json['deviceId'],
        deviceType: json['deviceType'],
        deviceName: json['deviceName'] != null ? json['deviceName'] : '',
        controlActions: json['controlActions'] != null
            ? Utils.dynamicListToStringList(json['controlActions'])
            : const [],
        measureActions: json['measureActions'] != null
            ? Utils.dynamicListToStringList(json['measureActions'])
            : const [],
        currentPasswordNumber: int.parse(json['currentPasswordNumber']),
        hmac: json['hmac'],
      );

      String password = '';
      if (devices.length > 0) {
        password = devices
            .firstWhere(
                (element) => element.deviceId == discoverResponse.getDeviceId())
            .knownPassword;
      }

      // Check hmac before additional processing
      if (verifyHmac) {
        String controlActions = '';
        if (discoverResponse.isValid()) {
          for (String s in discoverResponse.getControlActions()) {
            controlActions += '"$s"';
          }
        }
        String measureActions = '';
        if (discoverResponse.isValid()) {
          for (String s in discoverResponse.getMeasureActions()) {
            measureActions += '"$s"';
          }
        }
        String verifyString =
            '${ScpResponseDiscover.type}${discoverResponse.getDeviceId()}${discoverResponse.getDeviceType()}${discoverResponse.getDeviceName()}${controlActions}${measureActions}${discoverResponse.getCurrentPasswordNumber()}';
        Scp.getInstance().log('verify string:');
        Scp.getInstance().log(verifyString);
        if (await ScpCrypto()
            .verifyHMAC(verifyString, discoverResponse.getHmac(), password)) {
          return discoverResponse;
        }
      } else {
        print('Not verifying HMAC.');
        return discoverResponse;
      }
    } else {
      print('discover-response type not found');
      return ScpResponseDiscover();
    }
      return ScpResponseDiscover();
  }

  String getDeviceType() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceType;
    }
  }

  String getDeviceName() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceName;
    }
  }

  String getDeviceId() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _deviceId;
    }
  }

  List<String> getControlActions() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _controlActions;
    }
  }

  List<String> getMeasureActions() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _measureActions;
    }
  }

  int getCurrentPasswordNumber() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _currentPasswordNumber;
    }
  }

  String getHmac() {
    if (!isValid()) {
      throw new ResponseInvalidException();
    } else {
      return _hmac;
    }
  }

  bool isValid() {
    if (_deviceId != '' &&
        _deviceType != '' &&
        _hmac != '' ) {
      return true;
    }
    return false;
  }
}
