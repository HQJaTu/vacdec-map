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
from typing import Tuple
from lxml import etree  # lxml implements the ElementTree API, has better performance or more advanced features
from lxml.html import fromstring
import logging

log = logging.getLogger(__name__)

DEFAULT_LAYER_NAME = "Flags"


def _setup_logger() -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)
    log.setLevel(logging.DEBUG)


def import_map_svg(filename: str, layer_name: str) -> Tuple[etree.ElementTree, etree.Element]:
    parser = etree.XMLParser()
    tree = etree.parse(filename, parser)

    # <g inkscape:groupmode="layer"
    #    id="layer5"
    #    inkscape:label="Flags"
    #    style="display:inline">

    root = tree.getroot()
    namespaces_for_xpath = {ns: url for ns, url in root.nsmap.items() if ns}
    layer_name_encoded = fromstring(layer_name)
    layer = root.xpath(r'./svg:g[@inkscape:label="{}"]'.format(layer_name_encoded.text),
                       namespaces=namespaces_for_xpath)
    if not layer:
        raise ValueError("Inkscape layer '{}' not found in SVG!".format(layer_name))

    return tree, layer[0]


def output_flag_coordinates(tree: etree.ElementTree, layer: etree.Element) -> None:
    root = tree.getroot()
    namespaces_for_xpath = {ns: url for ns, url in root.nsmap.items() if ns}
    flag_images = layer.xpath(r'./svg:image', namespaces=namespaces_for_xpath)
    flag_coords = {}
    for flag in flag_images:
        alpha_2 = flag.attrib["id"][-2:]
        x = float(flag.attrib["x"])
        y = float(flag.attrib["y"])
        flag_coords[alpha_2] = {"x": x, "y": y}
    for alpha_2 in sorted(flag_coords.keys()):
        print('"{}": {},'.format(alpha_2, flag_coords[alpha_2]))


def main() -> None:
    parser = argparse.ArgumentParser(description='Extract current coordinates of all flags')
    parser.add_argument('world_map_svg_in', metavar="WORLD-MAP-SVG",
                        help='Input SVG-file')
    parser.add_argument('--layer-name', default=DEFAULT_LAYER_NAME,
                        help="Layer to embed flags into. Default: {}".format(DEFAULT_LAYER_NAME))
    args = parser.parse_args()
    _setup_logger()

    flag_svg, flags_layer = import_map_svg(args.world_map_svg_in, args.layer_name)
    output_flag_coordinates(flag_svg, flags_layer)


if __name__ == "__main__":
    main()
