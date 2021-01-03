/*
secure_control_protocol
InputValidation Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class InputValidation {
  static bool isNull(Object o) {
    if (o == null) {
      return true;
    }
    return false;
  }

  static bool isEmpty(Object o) {
    if (o == '') {
      return true;
    }
    return false;
  }

  static bool isIpAddress(String s) {
    // Check IPv4 dotted notation

    // Shortes "0.0.0.0" = 7, longest "255.255.255.255" = 15
    if (isNull(s) || isEmpty(s) || s.length < 7 || s.length > 15) {
      return false;
    }
    //Check regex
    RegExp regExp = new RegExp(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$",
        caseSensitive: false, multiLine: false);
    if (!regExp.hasMatch(s)) {
      return false;
    }
    ;
    // Check range of all fields
    // Split string
    List<String> octets = s.split('.');
    // Check range from 0 to 255 of each octet
    for (String octet in octets) {
      if (int.parse(octet) < 0 || int.parse(octet) > 255) {
        return false;
      }
    }
    return true;
  }

  static bool isSubnetMask(String s) {
    if (isNull(s) || isEmpty(s) || s.length > 2) {
      return false;
    }
    //Check regex
    RegExp regExp =
        new RegExp(r"^(\d{1,2})$", caseSensitive: false, multiLine: false);
    if (!regExp.hasMatch(s)) {
      return false;
    }
    ;
    if (int.parse(s) < 1 || int.parse(s) > 32) {
      return false;
    }

    return true;
  }
}
