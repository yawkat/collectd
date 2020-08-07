/**
 * collectd - src/corsair_rmi.c
 * Copyright (C) 2020       Jonas Konrad
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author:
 *   Jonas Konrad <me at yawk dot at>
 *
 * Adapted from https://github.com/notaz/corsairmi
 **/

#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include <fcntl.h>
#include <linux/hidraw.h>
#include <math.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef struct corsair_rmi_unit {
  int fd;
  const char *instance;
} corsair_rmi_unit;

static corsair_rmi_unit *open_rmi_hid(const char *path, bool skip_device_check,
                                      int *open_errno) {
  int fd = open(path, O_RDWR);
  if (fd == -1) {
    if (open_errno != NULL) {
      *open_errno = errno;
    }
    return NULL;
  }

  if (skip_device_check) {
    return NULL;
  }

  struct hidraw_devinfo devinfo;
  if (ioctl(fd, HIDIOCGRAWINFO, &devinfo) != 0) {
    P_WARNING("Failed to get HID info: %s", strerror(errno));
    goto close_return;
  }

  if (devinfo.vendor != 0x1b1c) {
    goto close_return;
  }

  switch (devinfo.product) {
  case 0x1c0a: /* RM650i */
  case 0x1c0b: /* RM750i */
  case 0x1c0c: /* RM850i */
  case 0x1c0d: /* RM1000i */
  case 0x1c04: /* HX650i */
  case 0x1c05: /* HX750i */
  case 0x1c06: /* HX850i */
  case 0x1c07: /* HX1000i */
  case 0x1c08: /* HX1200i */
    break;
  default:
    goto close_return;
  }

  corsair_rmi_unit *unit = malloc(sizeof(corsair_rmi_unit));
  unit->fd = fd;
  return unit;

close_return:
  if (close(fd) != 0) {
    P_WARNING("Failed to close HID: %s", strerror(errno));
  }
  return NULL;
}

static bool command(corsair_rmi_unit *unit, uint8_t cmd[3], uint8_t *outp,
                    size_t outs) {
  uint8_t send[65] = {0, cmd[0], cmd[1], cmd[2]};
  if (write(unit->fd, send, sizeof(send)) != sizeof(send)) {
    P_WARNING("Failed to write command: %s", strerror(errno));
    return false;
  }
  uint8_t recv[64];
  if (read(unit->fd, recv, sizeof(recv)) != sizeof(recv)) {
    P_WARNING("Failed to read response: %s", strerror(errno));
    return false;
  }
  if (recv[0] != cmd[0] || recv[1] != cmd[1]) {
    P_WARNING("Invalid response");
    return false;
  }
  if (outp != NULL) {
    memcpy(outp, recv + 2, outs < sizeof(recv) - 2 ? outs : sizeof(recv) - 2);
  }
  return true;
}

static bool read_register(corsair_rmi_unit *unit, uint8_t reg, uint8_t *outp,
                          size_t outs) {
  return command(unit, (uint8_t[3]){0x03, reg, 0x00}, outp, outs);
}

static bool read_register_16(corsair_rmi_unit *unit, uint8_t reg,
                             uint16_t *outp) {
  uint8_t tmp[2];
  if (!command(unit, (uint8_t[3]){0x03, reg, 0x00}, tmp, 2)) {
    return false;
  }
  *outp = tmp[0] | (uint16_t)((uint16_t)tmp[1] << 8u);
  return true;
}

static bool read_register_fp(corsair_rmi_unit *unit, uint8_t reg,
                             double *outp) {
  uint16_t tmp;
  if (!read_register_16(unit, reg, &tmp)) {
    return false;
  }
  P_INFO("%x", tmp);
  int16_t exponent = ((int16_t)tmp) >> 11;
  // bottom 11 bits, sign extended
  int16_t fraction = (int16_t)(tmp << 5) >> 5;
  *outp = (double)fraction * pow(2.0, exponent);
  return true;
}

static bool read_register_32(corsair_rmi_unit *unit, uint8_t reg,
                             uint32_t *outp) {
  uint8_t tmp[4];
  if (!command(unit, (uint8_t[3]){0x03, reg, 0x00}, tmp, 4)) {
    return false;
  }
  *outp = tmp[0] | (uint32_t)((uint32_t)tmp[1] << 8u) |
          (uint32_t)((uint32_t)tmp[2] << 16u) |
          (uint32_t)((uint32_t)tmp[3] << 24u);
  return true;
}

static void rmi_submit(corsair_rmi_unit *unit, const char *type,
                       const char *type_instance, value_t value) {
  value_list_t list = VALUE_LIST_INIT;
  list.values = &value;
  list.values_len = 1;
  sstrncpy(list.plugin, "corsair_rmi", sizeof(list.plugin));
  sstrncpy(list.plugin_instance, unit->instance, sizeof(list.plugin));
  sstrncpy(list.type, type, sizeof(list.type));
  sstrncpy(list.type_instance, type_instance, sizeof(list.type_instance));
  plugin_dispatch_values(&list);
}

static void read_and_submit_register_fp(corsair_rmi_unit *unit, int reg,
                                        char *type, char *type_instance) {
  double tmp;
  if (read_register_fp(unit, reg, &tmp)) {
    rmi_submit(unit, type, type_instance, (value_t){.gauge = tmp});
  } else {
    P_WARNING("Failed to read %s %s", type, type_instance);
  }
}

static int rmi_read_callback(user_data_t *user_data) {
  corsair_rmi_unit *unit = user_data->data;

  uint32_t powered; // seconds
  if (read_register_32(unit, 0xd1, &powered)) {
    rmi_submit(unit, "uptime", "powered", (value_t){.gauge = powered});
  } else {
    P_WARNING("Failed to read powered time");
  }
  uint32_t uptime; // seconds
  if (read_register_32(unit, 0xd2, &uptime)) {
    rmi_submit(unit, "uptime", "online", (value_t){.gauge = uptime});
  } else {
    P_WARNING("Failed to read uptime");
  }

  read_and_submit_register_fp(unit, 0x8d, "temperature", "1");
  read_and_submit_register_fp(unit, 0x8e, "temperature", "2");
  read_and_submit_register_fp(unit, 0x90, "fanspeed", "");
  read_and_submit_register_fp(unit, 0x88, "voltage", "in");
  read_and_submit_register_fp(unit, 0xee, "power", "in");

  for (uint8_t output = 0; output < 3; output++) {
    if (!command(unit, (uint8_t[3]){0x02, 0x00, output}, NULL, 0)) {
      P_WARNING("Failed to open output %d", output);
      continue;
    }
    char type_instance[5];
    ssnprintf(type_instance, sizeof(type_instance), "out%d", output);
    read_and_submit_register_fp(unit, 0x8b, "voltage", type_instance);
    read_and_submit_register_fp(unit, 0x8c, "current", type_instance);
    read_and_submit_register_fp(unit, 0x96, "power", type_instance);
  }
  // select output 0
  command(unit, (uint8_t[3]){0x02, 0x00, 0x00}, NULL, 0);
}

static int rmi_config(oconfig_item_t *ci) {
  char *forced_path = NULL;
  char *instance_name = "";
  bool skip_device_check = false;
  cdtime_t interval = 0;
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = &(ci->children[i]);
    if (strcasecmp("Path", child->key) == 0) {
      int status = cf_util_get_string(child, &forced_path);
      if (status != 0) {
        return status;
      }
    } else if (strcasecmp("SkipDeviceCheck", child->key) == 0) {
      int status = cf_util_get_boolean(child, &skip_device_check);
      if (status != 0) {
        return status;
      }
    } else if (strcasecmp("Interval", child->key) == 0) {
      int status = cf_util_get_cdtime(child, &interval);
      if (status != 0) {
        return status;
      }
    } else if (strcasecmp("Instance", child->key) == 0) {
      int status = cf_util_get_string(child, &instance_name);
      if (status != 0) {
        return status;
      }
    } else {
      P_WARNING("ignoring unknown config option %s.", child->key);
    }
  }
  corsair_rmi_unit *unit = NULL;
  if (forced_path == NULL) {
    if (skip_device_check) {
      // writing random data to HIDs could be dangerous
      P_ERROR("SkipDeviceCheck only allowed with explicit Path");
      return -1;
    }
    for (uint8_t i = 0; i < 16; i++) {
      char path[PATH_MAX];
      ssnprintf(path, sizeof(path), "/dev/hidraw%d", i);
      unit = open_rmi_hid(path, false, NULL);
      if (unit != NULL) {
        break;
      }
    }
  } else {
    int open_errno = 0;
    unit = open_rmi_hid(forced_path, skip_device_check, &open_errno);
    if (open_errno != 0) {
      P_WARNING("Failed to open HID: %s", strerror(open_errno));
    }
  }
  if (unit == NULL) {
    P_ERROR("No unit found.");
    return 1;
  }

  unit->instance = instance_name;

  uint8_t name_buffer[63] = {};
  uint8_t vendor_buffer[63] = {};
  uint8_t product_buffer[63] = {};
  command(unit, (uint8_t[3]){0xfe, 0x03, 0x00}, name_buffer,
          sizeof(name_buffer) - 1);
  read_register(unit, 0x99, vendor_buffer, sizeof(vendor_buffer) - 1);
  read_register(unit, 0x9a, product_buffer, sizeof(product_buffer) - 1);
  P_INFO("Unit registered. Name: '%s' Vendor: '%s' Product: '%s'", name_buffer,
         vendor_buffer, product_buffer);

  plugin_register_complex_read(NULL, "corsair_rmi", rmi_read_callback, interval,
                               &(user_data_t){.data = unit});
  return 0;
}

void module_register(void) {
  plugin_register_complex_config("corsair_rmi", rmi_config);
}
