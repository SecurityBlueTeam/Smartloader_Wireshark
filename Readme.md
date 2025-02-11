# Smartloader Wireshark plugin

This plugin is designed and tested on Wireshark 4.4.3 and is intended to decode C2 traffic for the Smartloader malware variant.

## Installing

Windows users are to unzip the zip file in `%APPDATA%\Wireshark\plugins`.
\*nix users are to unzip the zip file in `~/.local/lib/wireshark/plugins`.

## Configuring
In Preferences>Protocols>Smartloader you are able to enable/disable the plugin, and change the encryption key used by the malware.
