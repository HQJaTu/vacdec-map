#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# This file is part of vacdec-map.
# vacdec-map is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia

import os
import sys
import io
import argparse
import lxml # lxml implements the ElementTree API, has better performance or more advanced features
import logging

log = logging.getLogger(__name__)


def _setup_logger() -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)
    log.setLevel(logging.DEBUG)


def main() -> None:
    parser = argparse.ArgumentParser(description='World flags into world map embed tool')
    parser.add_argument('--destination-dir', metavar="DESTINATION-DIRECTORY",
                        help='Save downloaded files into the directory')
    args = parser.parse_args()
    _setup_logger()

    session = _get_http_client()
    list_of_flags = get_flag_list(session)
    download_flag_list(session, list_of_flags, args.destination_dir)


if __name__ == "__main__":
    main()
