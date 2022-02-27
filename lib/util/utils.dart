/*
secure_control_protocol
Utils Util Class
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2020 Benjamin Schilling
*/

class Utils {
  static List<String> dynamicListToStringList(List<dynamic> input) {
    List<String> output = List<String>.empty(growable: true);
    for (var i in input) {
      output.add('$i');
    }
    return output;
  }
}
