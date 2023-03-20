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

import datetime
import os
import sys
import io
import argparse
from typing import Tuple
from lxml import etree  # lxml implements the ElementTree API, has better performance or more advanced features
from lxml.html import fromstring
import base64
from vacdec_map import CountryStatistics
import logging

log = logging.getLogger(__name__)

DEFAULT_LAYER_NAME = "Flags"

VERTICAL_ALIGN_TOP = "top"
VERTICAL_ALIGN_MIDDLE = "middle"
VERTICAL_ALIGN_BOTTOM = "bottom"


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

    layer = _find_layer(tree, layer_name)
    if layer is None:
        raise ValueError("Inkscape layer '{}' not found in SVG!".format(layer_name))

    return tree, layer


def _find_layer(tree: etree.ElementTree, layer_name: str) -> etree.Element:
    root = tree.getroot()
    namespaces_for_xpath = {ns: url for ns, url in root.nsmap.items() if ns}
    # layers = root.xpath(r'./svg:g', namespaces={'svg': root.nsmap['svg']})
    layer_name_encoded = fromstring(layer_name)
    layer = root.xpath(r'./svg:g[@inkscape:label="{}"]'.format(layer_name_encoded.text),
                       namespaces=namespaces_for_xpath)
    if not layer:
        return None

    return layer[0]


def _find_text_element(tree: etree.ElementTree, text_element_id: str) -> etree.Element:
    root = tree.getroot()
    namespaces_for_xpath = {ns: url for ns, url in root.nsmap.items() if ns}
    text_element_id_encoded = fromstring(text_element_id)
    text_element = root.xpath(r'.//svg:tspan[@id="{}"]'.format(text_element_id_encoded.text),
                              namespaces=namespaces_for_xpath)
    if not text_element:
        return None

    return text_element[0]


def get_country_list(certs_dir: str) -> dict:
    stats_engine = CountryStatistics(certs_dir)
    stats = stats_engine.get_country_statistics()
    log.info("Got statistics for {} countries".format(len(stats)))

    return stats


def add_flags(flags_dir: str, tree: etree.ElementTree, layer: etree.Element, flags_to_add: dict):
    # Workflow:
    # 1) Edit with Inkscape
    # 2) run ./cli-utils/extract-flag-coords.py
    # 3) copy output here
    # 4) done!
    coords = {
        "ad": {'x': 1085.5621, 'y': 394.10989},
        "ae": {'x': 1563.8433, 'y': 592.81677},
        "al": {'x': 1243.8829, 'y': 415.71643},
        "am": {'x': 1467.4722, 'y': 422.884},
        "at": {'x': 1203.35, 'y': 344.36911},
        "az": {'x': 1502.1411, 'y': 422.04321},
        "be": {'x': 1115.4531, 'y': 308.54907},
        "bg": {'x': 1301.6404, 'y': 395.43692},
        "bh": {'x': 1527.0278, 'y': 559.00378},
        "bj": {'x': 1094.6628, 'y': 739.98236},
        "br": {'x': 531.23236, 'y': 912.87769},
        "ch": {'x': 1153.8079, 'y': 346.05908},
        "co": {'x': 349.85068, 'y': 796.84021},
        "cv": {'x': 831.10962, 'y': 668.24146},
        "cy": {'x': 1362.1937, 'y': 479.65173},
        "cz": {'x': 1215.5726, 'y': 320.03674},
        "de": {'x': 1182.2975, 'y': 299.79678},
        "dk": {'x': 1169.8425, 'y': 255.64351},
        "ee": {'x': 1289.8425, 'y': 230.25443},
        "es": {'x': 1048.1732, 'y': 428.47406},
        "fi": {'x': 1278.2059, 'y': 192.29105},
        "fo": {'x': 1030.6283, 'y': 170.3475},
        "fr": {'x': 1107.9016, 'y': 356.68839},
        "gb": {'x': 1077.5516, 'y': 296.68585},
        "ge": {'x': 1431.6068, 'y': 396.88776},
        "gr": {'x': 1276.4565, 'y': 447.18457},
        "hr": {'x': 1207.9301, 'y': 374.46396},
        "hu": {'x': 1245.3401, 'y': 353.27802},
        "hk": {'x': 2126.6086, 'y': 610.99976},
        "id": {'x': 2121.4058, 'y': 872.49768},
        "ie": {'x': 1024.7325, 'y': 290.08807},
        "il": {'x': 1392.0938, 'y': 508.71915},
        "is": {'x': 958.49701, 'y': 167.44846},
        "it": {'x': 1216.0157, 'y': 412.02322},
        "jo": {'x': 1402.2361, 'y': 529.67798},
        "kr": {'x': 2181.8081, 'y': 454.4686},
        "lb": {'x': 1395.8834, 'y': 483.37332},
        "li": {'x': 1178.8207, 'y': 339.95197},
        "lt": {'x': 1276.1283, 'y': 266.85205},
        "lu": {'x': 1145.2166, 'y': 320.45706},
        "lv": {'x': 1285.0343, 'y': 250.61453},
        "ma": {'x': 995.64288, 'y': 502.48758},
        "mc": {'x': 1137.429, 'y': 387.76968},
        "md": {'x': 1321.5739, 'y': 350.82819},
        "mg": {'x': 1468.0817, 'y': 1047.6863},
        "me": {'x': 1233.89, 'y': 383.5827},
        "mk": {'x': 1269.5107, 'y': 410.67072},
        "mt": {'x': 1209.1222, 'y': 467.86826},
        "my": {'x': 2035.04, 'y': 805.27478},
        "nl": {'x': 1131.7908, 'y': 291.68457},
        "no": {'x': 1144.7124, 'y': 197.56062},
        "nz": {'x': 2591.5256, 'y': 1262.5505},
        "om": {'x': 1588.8616, 'y': 631.32648},
        "pa": {'x': 313.80814, 'y': 752.33368},
        "pe": {'x': 312.6673, 'y': 923.81372},
        "pl": {'x': 1231.9153, 'y': 289.95309},
        "ph": {'x': 2192.5637, 'y': 703.7785},
        "pt": {'x': 997.79785, 'y': 430.19284},
        "ro": {'x': 1300.359, 'y': 367.39563},
        "rs": {'x': 1259.1129, 'y': 388.67386},
        "sc": {'x': 1562.5601, 'y': 885.22693},
        "se": {'x': 1205.4993, 'y': 204.00682},
        "sg": {'x': 2055.7974, 'y': 840.48474},
        "si": {'x': 1232.3268, 'y': 364.76022},
        "sk": {'x': 1249.8861, 'y': 332.47128},
        "sm": {'x': 1178.0165, 'y': 380.46756},
        "sv": {'x': 196.52727, 'y': 699.60449},
        "tg": {'x': 1074.299, 'y': 768.24188},
        "th": {'x': 2012.6313, 'y': 673.79614},
        "tn": {'x': 1153.8108, 'y': 479.65976},
        "tr": {'x': 1368.3807, 'y': 434.96408},
        "tw": {'x': 2213.7234, 'y': 577.28198},
        "ua": {'x': 1351.5739, 'y': 330.82819},
        "uy": {'x': 565.23145, 'y': 1200.6425},
        "va": {'x': 1183.5472, 'y': 405.28656},
        "vn": {'x': 2101.1248, 'y': 697.07733},
    }
    big_flags = ["br", "co", "cv", "id", "kr", "mg", "nz", "pe", "ph", "sc", "sv", "tw", "uy"]
    medium_flags = ["ae", "bh", "fi", "fo", "is", "hk", "ma", "my", "no", "om", "pa", "se", "sg", "th", "tn", "vn"]
    eu_flags = ['at', 'be', 'bg', 'hr', 'cy', 'cz', 'dk', 'ee', 'fi', 'fr',
                'de', 'gr', 'hu', 'ie', 'it', 'lv', 'lt', 'lu', 'mt', 'nl',
                'pl', 'pt', 'ro', 'sk', 'si', 'es', 'se']

    # Add all flags to the map
    noneu_cert_ages = {}
    seen_flags_count = 0
    seen_noneu_flag_count = 0
    seen_eu_flags = set(eu_flags)
    for country_alpha_2, country_data in flags_to_add.items():
        ca2 = country_alpha_2.lower()
        if ca2 not in coords:
            raise NotImplementedError("Country {} ({}) not implemented yet! Define coords first.".format(
                country_alpha_2, country_data[0].name)
            )

        seen_flags_count += 1
        log.debug("Adding {} ({}) flag".format(country_alpha_2, country_data[0].name))
        if ca2 in big_flags:
            width = 100
        elif ca2 in medium_flags:
            width = 50
        else:
            width = 30
        x = coords[ca2]["x"]
        y = coords[ca2]["y"]
        add_flag(flags_dir, tree, layer, country_alpha_2,
                 x, y, VERTICAL_ALIGN_TOP, width,
                 r"flag-{}")

        # Add flag to timeline too
        if ca2 not in eu_flags:
            noneu_cert_ages[country_data[1]] = country_alpha_2
            seen_noneu_flag_count += 1
        else:
            # EU-flags don't go to timeline
            seen_eu_flags.remove(ca2)

    log.info("Done adding {} flags to globe.".format(len(flags_to_add)))
    if seen_eu_flags:
        log.warning("Not added EU-countries: {}".format(', '.join(list(seen_eu_flags))))
    else:
        log.info("All EU-countries seen")

    # Update the map with today's date
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    updated_text_element = _find_text_element(tree, "map-updated-text")
    if updated_text_element is not None:
        updated_text_element.text = today
        log.info("Updated map with datestamp: {}".format(today))
    else:
        log.warning("Did not update datestamp. Text-element not found.")

    # Create timeline of non-EU countries
    timeline_layer = _find_layer(tree, "Timeline")
    if timeline_layer is not None:
        log.info("Updating non-EU flags timeline")
        tl_begin_text_element = _find_text_element(tree, "timeline-begin")
        tl_end_text_element = _find_text_element(tree, "timeline-end")
        ages = sorted(list(noneu_cert_ages.keys()))
        oldest_cert = ages[0]
        newest_cert = ages[-1:][0]
        log.debug("Oldest cert is {} ({})".format(noneu_cert_ages[oldest_cert], oldest_cert))
        log.debug("Newest cert is {} ({})".format(noneu_cert_ages[newest_cert], newest_cert))

        tl_begin_text_element.text = oldest_cert.strftime('%b %Y')
        tl_end_text_element.text = newest_cert.strftime('%b %Y')

        flags_y = 1490.0
        flags_current_y = flags_y
        flags_rise = 15
        flags_start_x = 730
        last_flag_x = 0
        last_flag_cleared_pixels = 35
        flags_width = 1655

        days = (newest_cert - oldest_cert).days
        day_in_pixels = flags_width / days
        for cert_date in ages:
            country_alpha_2 = noneu_cert_ages[cert_date]
            days = (cert_date - oldest_cert).days
            x_pos = flags_start_x + day_in_pixels * days
            if last_flag_x > x_pos - last_flag_cleared_pixels:
                # Too close to previous flag, need to make this flag higher.
                flags_current_y -= flags_rise
            else:
                # Enough space, make this flag on level
                flags_current_y = flags_y

            add_flag(flags_dir, tree, timeline_layer, country_alpha_2,
                     x_pos, flags_current_y, VERTICAL_ALIGN_BOTTOM, 40,
                     r"timeline-flag-{}")
            last_flag_x = x_pos
        log.info("Done adding {} flags into timeline.".format(len(noneu_cert_ages)))

    # Update the map with number of flags added
    flag_count = "Total of {} countries found, {} outside EU".format(seen_flags_count, seen_noneu_flag_count)
    updated_text_element = _find_text_element(tree, "map-countries-count-text")
    if updated_text_element is not None:
        updated_text_element.text = flag_count
        log.info("Updated map with flag count: {}".format(seen_flags_count))
    else:
        log.warning("Did not update flag count. Text-element not found.")

    log.info("Map update done.")


def add_flag(flags_dir: str, tree: etree.ElementTree, layer: etree.Element, alpha_2: str,
             flag_x: float, flag_y_in: float, vertical_align: str, width: int,
             id_format: str) -> None:
    """
    <image preserveAspectRatio="none"
        inkscape:svg-dpi="96"
        width="688.28601"
        height="481.80023"
        style="image-rendering:optimizeQuality"
        id="image6337"
        x="926.95697"
        y="237.90031"
        xlink:href="data:image/svg+xml;base64,12344555656"
        />
    :return:
    """
    flag_path = "{}/{}.svg".format(flags_dir, alpha_2)
    if not os.path.exists(flag_path):
        raise RuntimeError("Flag for country {} doesn't exist in {}!".format(alpha_2, flags_dir))

    svg_flag = open(flag_path, "rb").read()
    img_width, img_height = _get_svg_size(svg_flag)
    _, height = _calculate_new_size_for_fixed_width(img_width, img_height, width)
    if vertical_align == VERTICAL_ALIGN_TOP:
        flag_y = flag_y_in
    elif vertical_align == VERTICAL_ALIGN_BOTTOM:
        flag_y = flag_y_in - height
    else:
        raise ValueError("Don't know how to handle vertical align '{}'!".format(vertical_align))

    encoded = base64.b64encode(svg_flag).decode('ascii')

    root = tree.getroot()
    inkscape_ns = root.nsmap["inkscape"]
    xlink_ns = root.nsmap["xlink"]
    # <image/> https://developer.mozilla.org/en-US/docs/Web/SVG/Element/image
    flag_element = etree.Element("image", id=id_format.format(alpha_2.lower()))
    flag_element.attrib[etree.QName(inkscape_ns, "svg-dpi")] = "96"
    flag_element.attrib[
        "preserveAspectRatio"] = "None"  # https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/preserveAspectRatio
    flag_element.attrib["width"] = str(width)
    flag_element.attrib["height"] = str(height)
    flag_element.attrib["style"] = "image-rendering:optimizeQuality"
    flag_element.attrib["x"] = str(flag_x)
    flag_element.attrib["y"] = str(flag_y)
    flag_element.attrib[etree.QName(xlink_ns, "href")] = "data:image/svg+xml;base64," + encoded

    layer.append(flag_element)


def use_flag(flags_dir: str, tree: etree.ElementTree, layer: etree.Element,
             alpha_2: str, flag_x: float, flag_y: float, width: int) -> None:
    """
    <use preserveAspectRatio="none"
        inkscape:svg-dpi="96"
        width="688.28601"
        height="481.80023"
        style="image-rendering:optimizeQuality"
        id="image6337"
        x="926.95697"
        y="237.90031"
        xlink:href="#texture"
        />
    :return:
    """
    flag_path = "{}/{}.svg".format(flags_dir, alpha_2)
    if not os.path.exists(flag_path):
        raise RuntimeError("Flag for country {} doesn't exist in {}!".format(alpha_2, flags_dir))

    svg_flag = open(flag_path, "rb").read()
    img_width, img_height = _get_svg_size(svg_flag)
    _, height = _calculate_new_size_for_fixed_width(img_width, img_height, width)

    root = tree.getroot()
    inkscape_ns = root.nsmap["inkscape"]
    # xlink_ns = root.nsmap["xlink"]
    # <use/> https://developer.mozilla.org/en-US/docs/Web/SVG/Element/use
    flag_element = etree.Element("use", id="used-flag-{}".format(alpha_2.lower()))
    flag_element.attrib[etree.QName(inkscape_ns, "svg-dpi")] = "96"
    flag_element.attrib[
        "preserveAspectRatio"] = "None"  # https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/preserveAspectRatio
    flag_element.attrib["width"] = str(width)
    flag_element.attrib["height"] = str(height)
    flag_element.attrib["style"] = "image-rendering:optimizeQuality"
    flag_element.attrib["x"] = str(flag_x)
    flag_element.attrib["y"] = str(flag_y)
    # flag_element.attrib[etree.QName(xlink_ns, "href")] = "#flag-{}".format(alpha_2.lower())
    flag_element.attrib["href"] = "#flag-{}".format(alpha_2.lower())

    layer.append(flag_element)


def _get_svg_size(svg: bytes) -> Tuple[int, int]:
    root = etree.XML(svg)

    if "width" in root.attrib:
        # https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/width
        # https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/height
        if root.attrib["width"].endswith("px"):
            width = int(root.attrib["width"][:-2])
            height = int(root.attrib["height"][:-2])
        elif '.' in root.attrib["width"]:
            width = int(float(root.attrib["width"]))
            height = int(float(root.attrib["height"]))
        else:
            width = int(root.attrib["width"])
            height = int(root.attrib["height"])
    elif "viewBox" in root.attrib:
        # https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/viewBox
        parts = root.attrib["viewBox"].split(' ')
        width = int(parts[2])
        height = int(parts[3])
    else:
        raise RuntimeError("This SVG-file doesn't have width/height or viewBox!")

    return width, height


def _calculate_new_size_for_fixed_width(width: int, height: int, new_width: int) -> Tuple[int, int]:
    aspect = width / height
    new_height = new_width / aspect

    return new_width, new_height


def save_map(filename: str, tree: etree.ElementTree) -> None:
    root = tree.getroot()
    tree.write(filename, pretty_print=False)
    # str = etree.tostring(root, pretty_print=True)

    log.info("Wrote SVG into {}".format(filename))


def save_map_png_cairo(tree: etree.ElementTree, output_filename: str) -> None:
    """
    Cairo is nearly working
    :param tree:
    :param output_filename:
    :return:
    """
    from cairosvg import svg2png

    root = tree.getroot()
    svg = etree.tostring(root, pretty_print=False)
    svg2png(bytestring=svg, write_to=output_filename)
    log.info("Wrote PNG into {}".format(output_filename))


def save_map_png_pyvips(tree: etree.ElementTree, output_filename: str) -> None:
    import pyvips

    root = tree.getroot()
    svg = etree.tostring(root, pretty_print=False)
    # image = pyvips.Image.new_from_buffer(svg, options="", dpi=300)
    image = pyvips.Image.svgload_buffer(svg)
    image.write_to_file(output_filename)
    log.info("Wrote PNG into {}".format(output_filename))


def save_map_png_html2image(svg_filename: str, output_filename: str) -> None:
    from html2image import Html2Image
    hti = Html2Image(browser='firefox')
    hti.screenshot(other_file=svg_filename,
                   size=(4500, 2234),
                   save_as=output_filename)


def save_map_png_inkscape(svg_filename: str, output_filename: str) -> None:
    import subprocess

    # https://inkscape.org/doc/inkscape-man.html
    image_width = 4500
    image_height = 2234
    export_width = 3600
    export_start_x = 580
    args = [
        "/usr/bin/inkscape",
        "--without-gui",
        "-f", svg_filename,
        # "--export-area-page",
        "--export-area={}:{}:{}:{}".format(export_start_x, 0, export_width + export_start_x, image_height),
        "-w", str(export_width),
        "-h", str(image_height),
        "--export-png", output_filename
    ]
    print(args)
    subprocess.check_call(args)


def main() -> None:
    parser = argparse.ArgumentParser(description='World flags into world map embed tool')
    parser.add_argument('world_map_svg_in', metavar="WORLD-MAP-SVG",
                        help='Input SVG-file')
    parser.add_argument('flags_dir', metavar="ISO-3316-2-FLAG-SVG-DIRECTORY",
                        help='Save downloaded files into the directory')
    parser.add_argument('certs_dir', metavar="X.509-CERTIFICATE-DIRECTORY",
                        help='Directory containing already imported X.509 certificates')
    parser.add_argument('world_map_svg_out', metavar="RESULTING-SVG-MAP",
                        help='Input SVG-file')
    parser.add_argument('--layer-name', default=DEFAULT_LAYER_NAME,
                        help="Layer to embed flags into. Default: {}".format(DEFAULT_LAYER_NAME))
    parser.add_argument('--png-output-file',
                        help="Optionally render the outputted SVG into PNG")
    args = parser.parse_args()
    _setup_logger()

    if not os.path.exists(args.world_map_svg_in):
        log.error("Input file '{}' not found!".format(args.world_map_svg_in))
        exit(2)
    flag_svg, flags_layer = import_map_svg(args.world_map_svg_in, args.layer_name)

    country_cert_stats = get_country_list(args.certs_dir)
    add_flags(args.flags_dir, flag_svg, flags_layer, country_cert_stats)
    save_map(args.world_map_svg_out, flag_svg)

    if args.png_output_file:
        # save_map_png_cairo(flag_svg, args.png_output_file)
        # save_map_png_pyvips(flag_svg, args.png_output_file)
        # save_map_png_html2image(args.world_map_svg_out, args.png_output_file)
        save_map_png_inkscape(args.world_map_svg_out, args.png_output_file)


if __name__ == "__main__":
    main()
