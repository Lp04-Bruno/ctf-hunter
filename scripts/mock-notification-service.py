#!/usr/bin/python3
"""Minimal freedesktop notification service for package acceptance tests."""

import json
import os
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib


LOG_PATH = Path(os.environ["CTF_HUNTER_NOTIFICATION_LOG"])


class Notifications(dbus.service.Object):
    def __init__(self, bus: dbus.SessionBus) -> None:
        self._next_id = 1
        super().__init__(bus, "/org/freedesktop/Notifications")

    @dbus.service.method(
        "org.freedesktop.Notifications",
        in_signature="susssasa{sv}i",
        out_signature="u",
    )
    def Notify(
        self,
        app_name: str,
        replaces_id: int,
        app_icon: str,
        summary: str,
        body: str,
        actions: list[str],
        hints: dict[str, object],
        expire_timeout: int,
    ) -> dbus.UInt32:
        notification_id = int(replaces_id) or self._next_id
        self._next_id = max(self._next_id, notification_id + 1)
        record = {
            "app_name": str(app_name),
            "app_icon": str(app_icon),
            "summary": str(summary),
            "body": str(body),
            "actions": [str(action) for action in actions],
            "expire_timeout": int(expire_timeout),
        }
        with LOG_PATH.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")
        return dbus.UInt32(notification_id)

    @dbus.service.method(
        "org.freedesktop.Notifications", in_signature="u", out_signature=""
    )
    def CloseNotification(self, notification_id: int) -> None:
        del notification_id

    @dbus.service.method(
        "org.freedesktop.Notifications", in_signature="", out_signature="as"
    )
    def GetCapabilities(self) -> dbus.Array:
        return dbus.Array(["body"], signature="s")

    @dbus.service.method(
        "org.freedesktop.Notifications", in_signature="", out_signature="ssss"
    )
    def GetServerInformation(self) -> tuple[str, str, str, str]:
        return ("CTF Hunter Test Notifications", "CTF Hunter", "1", "1.2")


def main() -> None:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    bus_name = dbus.service.BusName("org.freedesktop.Notifications", bus=bus)
    notifications = Notifications(bus)
    GLib.MainLoop().run()
    del notifications, bus_name


if __name__ == "__main__":
    main()
