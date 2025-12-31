#!/bin/bash

# Sliver Implant Framework
# Copyright (C) 2022  Bishop Fox

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -e

HASHCAT_VER="6.2.6"

if ! [ -x "$(command -v curl)" ]; then
  echo 'Error: curl is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v zip)" ]; then
  echo 'Error: zip is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v unzip)" ]; then
  echo 'Error: unzip is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v tar)" ]; then
  echo 'Error: tar is not installed.' >&2
  exit 1
fi

echo "-----------------------------------------------------------------"
echo " Hashcat"
echo "-----------------------------------------------------------------"

echo "curl -L --fail --output ./assets/windows/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-windows_amd64.zip"
curl -L --fail --output ./assets/windows/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-windows_amd64.zip

echo "curl -L --fail --output ./assets/linux/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-linux_amd64.zip"
curl -L --fail --output ./assets/linux/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-linux_amd64.zip

echo "curl -L --fail --output ./assets/darwin/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-darwin_universal.zip"
curl -L --fail --output ./assets/darwin/amd64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-darwin_universal.zip

echo "curl -L --fail --output ./assets/darwin/arm64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-darwin_universal.zip"
curl -L --fail --output ./assets/darwin/arm64/hashcat.zip https://github.com/moloch--/hashcat/releases/download/v$HASHCAT_VER/hashcat-darwin_universal.zip

