#!/usr/bin/env python3

"""
Copyright (c) 2025 - 2026, Chris Perkins
Licence: BSD 3-Clause

From a given seed device, walks up the PTP Slave port path towards the Grand Master, using LLDP to
discover upstream devices. It captures PTP & interface information, then displays any possible
concerns it finds to aid troubleshooting.
Works with Arista EOS & Cisco NX-OS.

v0.4 - Bug fixes & added PTP interface commands check.
v0.3 - Bug fixes.
v0.2 - Fixed typos & improved formatting of output.
v0.1 - Initial development release.
"""

import sys
import re
from getpass import getpass
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler

# Thresholds to check against, adjust to your environment
MAX_OFFSET = 250
MAX_MEAN_PATH_DELAY = 1500
MAX_ACCURACY = 39
SYNCHED_CLOCK_CLASS = ["6", "13"]
HOLDOVER_CLOCK_CLASS = ["7", "14"]

# List of interface commands for PTP that should be present
# For example ["ptp", "ptp delay-request minimum interval 3", "ptp announce interval 2", "ptp sync interval 0"]
NXOS_PTP_COMMANDS = ["ptp"]
EOS_PTP_COMMANDS = ["ptp enable"]


def guess_device_type(remote_device):
    """Auto-detect device type"""
    try:
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
    except NetMikoAuthenticationException:
        print(
            f"Failed to execute CLI on {remote_device['host']} due to incorrect credentials."
        )
        return None
    except (NetMikoTimeoutException, SSHException):
        print(
            f"Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled."
        )
        return None
    except ValueError:
        print(
            f"Unsupported platform {remote_device['host']}, {remote_device['device_type']}."
        )
        return None
    else:
        return best_match


def main():
    seed_device = input("Seed device: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    device_list = [seed_device]
    ptp_hops = 0
    downstream_intf = []

    for target_device in device_list:
        try:
            # Auto-detect device type & establish correct SSH connection
            best_match = guess_device_type(
                {
                    "device_type": "autodetect",
                    "host": target_device,
                    "username": target_username,
                    "password": target_password,
                    "read_timeout_override": 60,
                    "fast_cli": False,
                }
            )
            if best_match is None:
                continue

            # print(f"\nConnecting to device: {target_device}, type: {best_match}")
            device = ConnectHandler(
                device_type=best_match,
                host=target_device,
                username=target_username,
                password=target_password,
                read_timeout_override=100,
                fast_cli=False,
                global_cmd_verify=False,
            )
        except NetMikoAuthenticationException:
            print(
                f"Failed to execute CLI on {target_device} due to incorrect credentials."
            )
            continue
        except (NetMikoTimeoutException, SSHException):
            print(
                f"Failed to execute CLI on {target_device} due to timeout or SSH not enabled."
            )
            continue
        except ValueError:
            print(f"Unsupported platform {target_device}, {best_match}.")
            continue
        else:
            parent_clock = grandmaster_clock = ptp_class = ptp_accuracy = (
                ptp_priority1
            ) = ptp_priority2 = ptp_path_delay = ptp_offset = ptp_steps = (
                tshoot_output
            ) = ""

            # Cisco NX-OS
            if best_match == "cisco_nxos":
                # Grab PTP interfaces
                upstream_intf = []
                cli_output = device.send_command("show ptp brief")
                for line in cli_output.splitlines():
                    intf = re.search(r"(Eth\d+\/\d+(\/\d+)?|Po\d+)\s+Slave", line)
                    if intf:
                        upstream_intf.append(intf.group(1).upper())

                    # First switch only, check all Master ports
                    if ptp_hops == 0:
                        intf = re.search(r"(Eth\d+\/\d+(\/\d+)?|Po\d+)\s+Master", line)
                        if intf:
                            downstream_intf.append(intf.group(1).upper())

                # Sanity check
                if not upstream_intf:
                    print(f"No PTP slave interfaces found on device {target_device}.")
                    continue

                # Grab PTP parent clock, grand master, class, accuracy, priority1 & priority2
                cli_output = device.send_command("show ptp parent")
                for line in cli_output.splitlines():
                    if not parent_clock:
                        parent_clock = re.search(
                            r"Parent Clock Identity:\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                            line,
                        )
                        parent_clock = parent_clock.group(1) if parent_clock else ""
                    if not grandmaster_clock:
                        grandmaster_clock = re.search(
                            r"Grandmaster Clock Identity:\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                            line,
                        )
                        grandmaster_clock = (
                            grandmaster_clock.group(1) if grandmaster_clock else ""
                        )
                    if not ptp_class:
                        ptp_class = re.search(
                            r"Class:\s+(\d+)",
                            line,
                        )
                        ptp_class = ptp_class.group(1) if ptp_class else ""
                    if not ptp_accuracy:
                        ptp_accuracy = re.search(
                            r"Accuracy:\s(\d+)",
                            line,
                        )
                        ptp_accuracy = ptp_accuracy.group(1) if ptp_accuracy else ""
                    if not ptp_priority1:
                        ptp_priority1 = re.search(
                            r"Priority1:\s(\d+)",
                            line,
                        )
                        ptp_priority1 = ptp_priority1.group(1) if ptp_priority1 else ""
                    if not ptp_priority2:
                        ptp_priority2 = re.search(
                            r"Priority2:\s(\d+)",
                            line,
                        )
                        ptp_priority2 = ptp_priority2.group(1) if ptp_priority2 else ""

                # Grab PTP offset, mean path delay & steps removed
                cli_output = device.send_command("show ptp clock")
                for line in cli_output.splitlines():
                    if not ptp_offset:
                        ptp_offset = re.search(
                            r"Offset From Master :\s+(\-?\d+)",
                            line,
                        )
                        ptp_offset = ptp_offset.group(1) if ptp_offset else ""
                    if not ptp_path_delay:
                        ptp_path_delay = re.search(r"Mean Path Delay :\s+(\d+)", line)
                        ptp_path_delay = (
                            ptp_path_delay.group(1) if ptp_path_delay else ""
                        )
                    if not ptp_steps:
                        ptp_steps = re.search(
                            r"Steps removed :\s+(\d+)",
                            line,
                        )
                        ptp_steps = ptp_steps.group(1) if ptp_steps else ""

                # Check clock class & accuracy against thresholds
                try:
                    if ptp_class in HOLDOVER_CLOCK_CLASS:
                        tshoot_output += f"Clock Class was synched to GNSS, currently in holdover: {ptp_class}\n"
                    elif ptp_class not in SYNCHED_CLOCK_CLASS:
                        tshoot_output += f"Clock Class isn't synched to GNSS or in holdover: {ptp_class}\n"
                    if "x" in ptp_accuracy:
                        accuracy = int(ptp_accuracy[2:], 16)
                    else:
                        accuracy = int(ptp_accuracy)
                    if accuracy > MAX_ACCURACY:
                        tshoot_output += (
                            f"Clock Accuracy exceeds threhold: {accuracy}\n"
                        )
                except ValueError:
                    pass

                # Check historical offset & mean path delay values against thresholds
                cli_output = device.send_command("show ptp corrections")
                for line in cli_output.splitlines():
                    offset_path_delay = re.search(
                        r"(Eth\d+\/\d+(\/\d+)?|Po\d+)\s+([\w:]+\s+){6}\s+(\-?\d+)\s+(\d+)",
                        line,
                    )
                    offset = offset_path_delay.group(4) if offset_path_delay else ""
                    path_delay = offset_path_delay.group(5) if offset_path_delay else ""
                    try:
                        if offset:
                            offset = int(offset)
                        if path_delay:
                            path_delay = int(path_delay)
                    except ValueError:
                        continue
                    else:
                        if offset and path_delay:
                            if (
                                offset > MAX_OFFSET
                                or offset < -MAX_OFFSET
                                or path_delay > MAX_MEAN_PATH_DELAY
                            ):
                                tshoot_output += f"Offset From Master and/or Mean Path Delay exceeds threshold:\n{cli_output}\n"
                                break

                print(
                    f"\nHop {ptp_hops}, {target_device}\n"
                    f"Grandmaster Clock: {grandmaster_clock}\n"
                    f"Parent Clock: {parent_clock}\n"
                    f"Class: {ptp_class}\n"
                    f"Accuracy: {ptp_accuracy}\n"
                    f"Priority1: {ptp_priority1}\n"
                    f"Priority2: {ptp_priority2}\n"
                    f"Offset From Master: {ptp_offset}\n"
                    f"Mean Path Delay: {ptp_path_delay}\n"
                    f"Steps removed: {ptp_steps}"
                )
                if tshoot_output:
                    print("\nPossible Issues:")
                    print(tshoot_output)
                    tshoot_output = ""

                print("\nPTP Syslog Events:")
                print(device.send_command("show logging | include PTP"))

                # Check PTP master interface configuration, find port-channel (if applicable)
                if downstream_intf:
                    cli_output = device.send_command(
                        f"show run interface {downstream_intf[0]}"
                    )
                    port_channel = re.search(r"channel-group (\d+)", cli_output)
                    if port_channel:
                        downstream_intf.append(f"PO{port_channel.group(1)}")

                print("\nPTP Downstream Interface(s):")
                for intf in downstream_intf:
                    # Check for interface flaps, errors or discards
                    cli_output = device.send_command(f"show interface {intf}")
                    int_description = re.search(r"Description: (.+)\n", cli_output)
                    int_description = (
                        int_description.group(1).rstrip() if int_description else ""
                    )
                    print(f"\n{intf} '{int_description}'")

                    for line in cli_output.splitlines():
                        flapped = re.search(r"Last link flapped\s+([\w:]+)", line)
                        if flapped:
                            tshoot_output = cli_output
                            break
                        input_errors = re.search(
                            r"(\d+) runts\s+(\d+) giants\s+(\d+) CRC\s+(\d+) no buffer",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input error\s+(\d+) short frame\s+(\d+) overrun\s+(\d+) underrun\s+(\d+) ignored",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                                or input_errors.group(5) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) watchdog\s+(\d+) bad etype drop\s+(\d+) bad proto drop\s+(\d+) if down drop",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input with dribble\s+(\d+) input discard",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) output error\s+(\d+) collision\s+(\d+) deferred\s+(\d+) late collision",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                                or output_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) lost carrier\s+(\d+) no carrier\s+(\d+) babble\s+(\d+) output discard",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                                or output_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break

                    if tshoot_output:
                        print("\nPossible Issues in Interface Statistics:")
                        print(tshoot_output)

                    # Check ethernet interface config for required PTP commands
                    if intf[0][:2] == "ET":
                        cli_output = device.send_command(f"show run interface {intf}")
                        ptp_commands = [
                            x.strip()
                            for x in cli_output.splitlines()
                            if x.strip() in NXOS_PTP_COMMANDS
                        ]
                        if len(ptp_commands) != len(NXOS_PTP_COMMANDS):
                            ptp_commands = [
                                x for x in NXOS_PTP_COMMANDS if x not in ptp_commands
                            ]
                            print("\nMissing PTP Interface Commands:")
                            print(f"{'\n'.join(ptp_commands)}")

                print("\nPTP Upstream Interface(s):")
                for intf in upstream_intf:
                    # Check for interface flaps, errors or discards
                    cli_output = device.send_command(f"show interface {intf}")
                    int_description = re.search(r"Description: (.+)\n", cli_output)
                    int_description = (
                        int_description.group(1).rstrip() if int_description else ""
                    )
                    print(f"\n{intf} '{int_description}'")

                    for line in cli_output.splitlines():
                        flapped = re.search(r"Last link flapped ([\w:]+)", line)
                        if flapped:
                            tshoot_output = cli_output
                            break
                        input_errors = re.search(
                            r"(\d+) runts\s+(\d+) giants\s+(\d+) CRC\s+(\d+) no buffer",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input error\s+(\d+) short frame\s+(\d+) overrun\s+(\d+) underrun\s+(\d+) ignored",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                                or input_errors.group(5) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) watchdog\s+(\d+) bad etype drop\s+(\d+) bad proto drop\s+(\d+) if down drop",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input with dribble\s+(\d+) input discard",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) output error\s+(\d+) collision\s+(\d+) deferred\s+(\d+) late collision",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                                or output_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) lost carrier\s+(\d+) no carrier\s+(\d+) babble\s+(\d+) output discard",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                                or output_errors.group(4) != "0"
                            ):
                                tshoot_output = cli_output
                                break

                    if tshoot_output:
                        print("\nPossible Issues in Interface Statistics:")
                        print(tshoot_output)

                    # Check ethernet interface config for required PTP commands
                    if intf[0][:2] == "ET":
                        cli_output = device.send_command(f"show run interface {intf}")
                        ptp_commands = [
                            x.strip()
                            for x in cli_output.splitlines()
                            if x.strip() in NXOS_PTP_COMMANDS
                        ]
                        if len(ptp_commands) != len(NXOS_PTP_COMMANDS):
                            ptp_commands = [
                                x for x in NXOS_PTP_COMMANDS if x not in ptp_commands
                            ]
                            print("\nMissing PTP Interface Commands:")
                            print(f"{'\n'.join(ptp_commands)}")

                # Grab LLDP neighbours & parse, noting the interfaces the upstream device connected to us
                if [x for x in upstream_intf if x[:2] == "ET"]:
                    cli_output = device.send_command(
                        f"show lldp neighbors interface {','.join([x for x in upstream_intf if x[:2] == 'ET'])}"
                    )

                    # Find column heading line
                    cntr = 0
                    for line in cli_output.splitlines():
                        cntr += 1
                        if "Device ID" in line:
                            break
                    hostname = None
                    downstream_intf = []
                    for line in cli_output.splitlines()[cntr:]:
                        words = line.split()
                        # Only parse valid LLDP neighbours entries
                        if not re.search(r"Total entries displayed", line) and words:
                            if hostname is None:
                                hostname = words[0].split(".")[0]
                            # If line is more than just hostname, parse interfaces
                            if len(words) > 1:
                                # Kludge for if there's no gap between hostname & local interface, IOS & IOS XE only
                                if best_match == "cisco_nxos" or len(words) != 4:
                                    local = words[0]
                                    remote = words[-1]
                                else:
                                    local = words[0][20:].strip()
                                    remote = words[-1]
                                # Note upstream device's interface
                                if remote.upper() not in downstream_intf:
                                    downstream_intf.append(remote.upper())
                                # Add newly found devices to the list
                                if hostname.upper() not in device_list:
                                    device_list.append(hostname.upper())
                                    ptp_hops += 1
                                hostname = None
                device.disconnect()

            # Arista EOS
            elif best_match == "arista_eos":
                # Grab PTP interfaces
                upstream_intf = []
                cli_output = device.send_command("show ptp")
                for line in cli_output.splitlines():
                    intf = re.search(r"(Et\d+(\/\d+)?|Po\d+)(,[\s\w]+)?\s+Slave", line)
                    if intf:
                        upstream_intf.append(intf.group(1).upper())

                    # First switch only, check all Master ports
                    if ptp_hops == 0:
                        intf = re.search(
                            r"(Et\d+(\/\d+)?|Po\d+)(,[\s\w]+)?\s+Master", line
                        )
                        if intf:
                            downstream_intf.append(intf.group(1).upper())

                # Sanity check
                if not upstream_intf:
                    print(f"No PTP slave interfaces found on device {target_device}.")
                    continue

                # Grab PTP parent clock, grand master, class, accuracy, priority1 & priority2
                cli_output = device.send_command("show ptp masters")
                for line in cli_output.splitlines():
                    if not parent_clock:
                        parent_clock = re.search(
                            r"Parent Clock Identity:\s+0x([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                            line,
                        )
                        parent_clock = parent_clock.group(1) if parent_clock else ""
                    if not grandmaster_clock:
                        grandmaster_clock = re.search(
                            r"Grandmaster Clock Identity:\s+0x([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                            line,
                        )
                        grandmaster_clock = (
                            grandmaster_clock.group(1) if grandmaster_clock else ""
                        )
                    if not ptp_class:
                        ptp_class = re.search(
                            r"Class:\s+(\d+)",
                            line,
                        )
                        ptp_class = ptp_class.group(1) if ptp_class else ""
                    if not ptp_accuracy:
                        ptp_accuracy = re.search(
                            r"Accuracy:\s(0x\d+)",
                            line,
                        )
                        ptp_accuracy = ptp_accuracy.group(1) if ptp_accuracy else ""
                    if not ptp_priority1:
                        ptp_priority1 = re.search(
                            r"Priority1:\s(\d+)",
                            line,
                        )
                        ptp_priority1 = ptp_priority1.group(1) if ptp_priority1 else ""
                    if not ptp_priority2:
                        ptp_priority2 = re.search(
                            r"Priority2:\s(\d+)",
                            line,
                        )
                        ptp_priority2 = ptp_priority2.group(1) if ptp_priority2 else ""

                # Grab PTP offset, mean path delay & steps removed
                cli_output = device.send_command("show ptp local-clock")
                for line in cli_output.splitlines():
                    if not ptp_offset:
                        ptp_offset = re.search(
                            r"Offset From Master \(nanoseconds\):\s+(\-?\d+)",
                            line,
                        )
                        ptp_offset = ptp_offset.group(1) if ptp_offset else ""
                    if not ptp_path_delay:
                        ptp_path_delay = re.search(r"Mean Path Delay:\s+(\d+)", line)
                        ptp_path_delay = (
                            ptp_path_delay.group(1) if ptp_path_delay else ""
                        )
                    if not ptp_steps:
                        ptp_steps = re.search(
                            r"Steps Removed:\s+(\d+)",
                            line,
                        )
                        ptp_steps = ptp_steps.group(1) if ptp_steps else ""

                # Check clock class & accuracy against thresholds
                try:
                    if ptp_class in HOLDOVER_CLOCK_CLASS:
                        tshoot_output += f"Clock Class was synched to GNSS, currently in holdover: {ptp_class}\n"
                    elif ptp_class not in SYNCHED_CLOCK_CLASS:
                        tshoot_output += f"Clock Class isn't synched to GNSS or in holdover: {ptp_class}\n"
                    if "x" in ptp_accuracy:
                        accuracy = int(ptp_accuracy[2:], 16)
                    else:
                        accuracy = int(ptp_accuracy)
                    if accuracy > MAX_ACCURACY:
                        tshoot_output += (
                            f"Clock Accuracy exceeds threhold: {accuracy}\n"
                        )
                except ValueError:
                    pass

                # Check historical offset & mean path delay values against thresholds
                cli_output = device.send_command("show ptp monitor")
                for line in cli_output.splitlines():
                    offset_path_delay = re.search(
                        r"(Et\d+(\/\d+)?|Po\d+)\s+([\w:\.]+\s){5}\s+(\-?\d+)\s+(\d+)",
                        line,
                    )
                    offset = offset_path_delay.group(4) if offset_path_delay else ""
                    path_delay = offset_path_delay.group(5) if offset_path_delay else ""
                    try:
                        if offset:
                            offset = int(offset)
                        if path_delay:
                            path_delay = int(path_delay)
                    except ValueError:
                        continue
                    else:
                        if offset and path_delay:
                            if (
                                offset > MAX_OFFSET
                                or offset < -MAX_OFFSET
                                or path_delay > MAX_MEAN_PATH_DELAY
                            ):
                                tshoot_output += f"Offset From Master and/or Mean Path Delay exceeds threshold:\n{cli_output}\n"
                                break

                print(
                    f"\nHop {ptp_hops}, {target_device}\n"
                    f"Grandmaster Clock: {grandmaster_clock}\n"
                    f"Parent Clock: {parent_clock}\n"
                    f"Class: {ptp_class}\n"
                    f"Accuracy: {ptp_accuracy}\n"
                    f"Priority1: {ptp_priority1}\n"
                    f"Priority2: {ptp_priority2}\n"
                    f"Offset From Master: {ptp_offset}\n"
                    f"Mean Path Delay: {ptp_path_delay}\n"
                    f"Steps removed: {ptp_steps}"
                )
                if tshoot_output:
                    print("\nPossible Issues:")
                    print(tshoot_output)
                    tshoot_output = ""

                print("\nPTP Syslog Events:")
                print(device.send_command("show logging | include PTP"))

                # Check PTP master interface configuration, find port-channel (if applicable)
                if downstream_intf:
                    cli_output = device.send_command(
                        f"show run interface {downstream_intf[0]}"
                    )
                    port_channel = re.search(r"channel-group (\d+)", cli_output)
                    if port_channel:
                        downstream_intf.append(f"PO{port_channel.group(1)}")

                print("\nPTP Downstream Interface(s):")
                for intf in downstream_intf:
                    # Check for interface flaps, errors or discards
                    cli_output = device.send_command(f"show interface {intf}")
                    int_description = re.search(r"Description: (.+)\n", cli_output)
                    int_description = (
                        int_description.group(1).rstrip() if int_description else ""
                    )
                    print(f"\n{intf} '{int_description}'")

                    for line in cli_output.splitlines():
                        flapped = re.search(
                            r"(\d+) link status changes since last clear", line
                        )
                        if flapped:
                            if flapped.group(1) != "0":
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) runts, (\d+) giants",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input errors, (\d+) CRC, (\d+) alignment, (\d+) symbol, (\d+) input discards",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                                or input_errors.group(5) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) output errors, (\d+) collisions",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) late collision, (\d+) deferred, (\d+) output discards",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                            ):
                                tshoot_output = cli_output
                                break

                    if tshoot_output:
                        print("\nPossible Issues in Interface Statistics:")
                        print(tshoot_output)

                    # Check ethernet or port-channel interface config for required PTP commands
                    cli_output = device.send_command(f"show run interface {intf}")
                    port_channel = re.search(r"channel-group (\d+)", cli_output)
                    if not port_channel:
                        ptp_commands = [
                            x.strip()
                            for x in cli_output.splitlines()
                            if x.strip() in EOS_PTP_COMMANDS
                        ]
                        if len(ptp_commands) != len(EOS_PTP_COMMANDS):
                            ptp_commands = [
                                x for x in EOS_PTP_COMMANDS if x not in ptp_commands
                            ]
                            print("\nMissing PTP Interface Commands:")
                            print(f"{'\n'.join(ptp_commands)}")

                # Check PTP slave interface configuration, find port-channel member interfaces (if applicable)
                if upstream_intf[0][:2] == "PO":
                    cli_output = device.send_command(
                        f"show run interface {upstream_intf[0]}"
                    )
                    for line in cli_output.splitlines():
                        member_port = re.search(
                            r"Transmit member: (Ethernet\d+(\/\d+)?)", line
                        )
                        member_port = (
                            member_port.group(1).upper() if member_port else ""
                        )
                        if member_port:
                            if member_port not in upstream_intf:
                                upstream_intf.append(member_port)

                print("\nPTP Upstream Interface(s):")
                for intf in upstream_intf:
                    # Check for interface flaps, errors or discards
                    cli_output = device.send_command(f"show interface {intf}")
                    int_description = re.search(r"Description: (.+)\n", cli_output)
                    int_description = (
                        int_description.group(1).rstrip() if int_description else ""
                    )
                    print(f"\n{intf} '{int_description}'")

                    for line in cli_output.splitlines():
                        flapped = re.search(
                            r"(\d+) link status changes since last clear", line
                        )
                        if flapped:
                            if flapped.group(1) != "0":
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) runts, (\d+) giants",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        input_errors = re.search(
                            r"(\d+) input errors, (\d+) CRC, (\d+) alignment, (\d+) symbol, (\d+) input discards",
                            line,
                        )
                        if input_errors:
                            if (
                                input_errors.group(1) != "0"
                                or input_errors.group(2) != "0"
                                or input_errors.group(3) != "0"
                                or input_errors.group(4) != "0"
                                or input_errors.group(5) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) output errors, (\d+) collisions",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                            ):
                                tshoot_output = cli_output
                                break
                        output_errors = re.search(
                            r"(\d+) late collision, (\d+) deferred, (\d+) output discards",
                            line,
                        )
                        if output_errors:
                            if (
                                output_errors.group(1) != "0"
                                or output_errors.group(2) != "0"
                                or output_errors.group(3) != "0"
                            ):
                                tshoot_output = cli_output
                                break

                    if tshoot_output:
                        print("\nPossible Issues in Interface Statistics:")
                        print(tshoot_output)

                    # Check ethernet or port-channel interface config for required PTP commands
                    cli_output = device.send_command(f"show run interface {intf}")
                    port_channel = re.search(r"channel-group (\d+)", cli_output)
                    if not port_channel:
                        ptp_commands = [
                            x.strip()
                            for x in cli_output.splitlines()
                            if x.strip() in EOS_PTP_COMMANDS
                        ]
                        if len(ptp_commands) != len(EOS_PTP_COMMANDS):
                            ptp_commands = [
                                x for x in EOS_PTP_COMMANDS if x not in ptp_commands
                            ]
                            print("\nMissing PTP Interface Commands:")
                            print(f"{'\n'.join(ptp_commands)}")

                # Grab LLDP neighbours & parse, noting the interfaces the upstream device connected to us
                if [x for x in upstream_intf if x[:2] == "ET"]:
                    cli_output = device.send_command(
                        f"show lldp neighbors {','.join([x for x in upstream_intf if x[:2] == 'ET'])}"
                    )
                    # Find column heading line
                    cntr = 0
                    for line in cli_output.splitlines():
                        cntr += 1
                        if "Neighbor Device ID" in line:
                            cntr += 1
                            break
                    hostname = None
                    downstream_intf = []
                    for line in cli_output.splitlines()[cntr:]:
                        words = line.split()
                        # Only parse valid LLDP neighbours entries
                        if words:
                            if hostname is None:
                                hostname = words.pop(1).split(".")[0]
                            if len(words) > 1:
                                local = words[0]
                                remote = words[-2]
                                # Note upstream device's interface
                                if remote.upper() not in downstream_intf:
                                    downstream_intf.append(remote.upper())
                                # Add newly found devices to the list
                                if hostname.upper() not in device_list:
                                    device_list.append(hostname.upper())
                                    ptp_hops += 1
                                hostname = None
                device.disconnect()

            # Unsupported, disconnect
            else:
                device.disconnect()

    sys.exit(0)


if __name__ == "__main__":
    main()
