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
import requests
import re
from pycountry import countries, db as pycountry_db
import shutil
import logging

log = logging.getLogger(__name__)
WIKIPEDIA_API_BASE_URL = r"https://en.wikipedia.org/w/api.php"
WIKIPEDIA_FLAGS_PAGE_TITLE = r"Gallery_of_sovereign_state_flags"
rest_user_agent = 'FlagImporter/0.1'
timeout = 5.0


def _setup_logger() -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)
    log.setLevel(logging.DEBUG)


def _get_http_client() -> requests.Session:
    headers = {
        'Accept': 'application/json',
        'User-Agent': rest_user_agent,
    }
    s = requests.Session()
    s.headers.update(headers)

    return s


def get_flag_list(s: requests.Session) -> dict:
    extra_flags = [
        ("FO", "Faroe Islands", "File:Flag of the Faroe Islands.svg")
    ]

    page_query = {
        "action": "parse",
        "format": "json",
        "page": WIKIPEDIA_FLAGS_PAGE_TITLE,
        "prop": "wikitext",
        "formatversion": 2,
    }
    log.debug("Going for {} to get list of flags".format(WIKIPEDIA_API_BASE_URL))
    response = s.get(WIKIPEDIA_API_BASE_URL, params=page_query, timeout=timeout)
    if response.status_code != 200:
        raise RuntimeError("Failed to request page data from API! HTTP/{}".format(response.status_code))
    page_data = response.json()

    # Helping hand to bridge the cap between Wikipedia and pycountry
    # Data from: https://github.com/flyingcircusio/pycountry/blob/master/src/pycountry/databases/iso3166-1.json
    exceptions = {
        "Cape Verde": "Cabo Verde",
        "Democratic Republic of the Congo": "Congo, The Democratic Republic of the",
        "East Timor": "Timor-Leste",
        "Ivory Coast": "Côte d'Ivoire",
        "Laos": "Lao People's Democratic Republic",
        "Artsakh": None,
        # unrecognized country in the South Caucasus which is de facto independent, de jure considered a part of Azerbaijan,
        "Northern Cyprus": None,  # Flag of the Turkish Republic of Northern Cyprus
        "Somaliland": None,
        # de facto sovereign state in the Horn of Africa, considered by most states to be part of Somalia
        "South Ossetia": None,
        # Georgian government and most members of the United Nations consider the territory part of Georgia
        "Transnistria": None,  # an unrecognised breakaway state that is internationally recognised as part of Moldova
        "North Korea": "Korea, Democratic People's Republic of",
        "South Korea": "Korea, Republic of",
    }

    flags_out = {}
    flag_iter = re.finditer(r'(File:[^|]+)\|\[\[[^|]+\|([^]]+)]]', page_data["parse"]["wikitext"])
    for flag_match in flag_iter:
        country_name = flag_match.group(2)
        flag_file = flag_match.group(1)
        if not country_name or not flag_file:
            raise RuntimeError("Fail! Country: '{}', Flag file: '{}}'".format(country_name, flag_file))

        if country_name in exceptions:
            if not exceptions[country_name]:
                # Skip this one
                log.debug("{}: Skipped!".format(country_name))
                continue
            country_name = exceptions[country_name]

        # Go query!
        try:
            country_data = countries.lookup(country_name)
        except LookupError:
            country_data = None
        if not country_data:
            try:
                country_data = countries.search_fuzzy(country_name)
            except LookupError:
                country_data = None
            if not country_data:
                raise LookupError(
                    "Country '{}' not found in DB nor exception-list! Cannot proceed.".format(country_name))
            country_data = country_data[0]

        flag_data = _get_flag_data(s, country_data, country_name, flag_file)
        flags_out[country_data.alpha_2] = flag_data
        flag_file = "File:Flag of the Faroe Islands.svg"
        log.debug("{} ({}): {}, URL: {}".format(country_name, country_data.alpha_2, flag_file, flag_data['image_url']))

    log.info("Done listing {} flags from Wikipedia.".format(len(flags_out)))

    for extra in extra_flags:
        country_data = countries.get(alpha_2=extra[0])
        country_name = extra[1]
        flag_file = extra[2]
        flag_data = _get_flag_data(s, country_data, country_name, flag_file)
        log.debug("Extra flag {} ({}): {}, URL: {}".format(country_name, country_data.alpha_2, flag_file, flag_data['image_url']))
        flags_out[country_data.alpha_2] = flag_data

    log.info("Did total of {} flags.".format(len(flags_out)))

    return flags_out


def _get_flag_data(s: requests.Session, country_data: pycountry_db.Data,
                   country_name: str, flag_file: str) -> dict:
    alpha_2 = country_data.alpha_2
    db_name = country_data.name

    image_query = {
        "action": "query",
        "format": "json",
        "titles": flag_file,
        "prop": "imageinfo",
        "iiprop": "url",
    }

    response = s.get(WIKIPEDIA_API_BASE_URL, params=image_query, timeout=timeout)
    if response.status_code != 200:
        raise RuntimeError("Failed to request image data from API! HTTP/{}".format(response.status_code))
    image_data = response.json()
    # Wikipedia API internal working:
    # If the flag is a link to a page (about the flag), then page ID will be that page's ID.
    # If not, then page ID will be -1. We just need to figure out which is the case here.
    page_id = list(image_data["query"]["pages"].keys())[0]
    image_url = image_data["query"]["pages"][page_id]["imageinfo"][0]["url"]

    flag_data = {
        'wikipedia_name': country_name,
        'ISO-3316_name': db_name,
        'flag_file': flag_file,
        'image_url': image_url,
    }

    return flag_data


def download_flag_list(s: requests.Session, list_of_flags: dict, dest_dir: str) -> None:
    if dest_dir:
        if os.path.exists(dest_dir):
            if not os.path.isdir(dest_dir):
                raise ValueError("Destination directory '{}' is not a directory!".format(dest_dir))
        else:
            os.mkdir(dest_dir)
    else:
        dest_dir = '.'

    saved_flag_count = 0
    for alpha_2, country_data in list_of_flags.items():
        image_url = country_data['image_url']
        log.debug("Going for {} to get list of flags".format(image_url))
        response = s.get(image_url, timeout=timeout, stream=True)
        if response.status_code != 200:
            raise RuntimeError("Failed to request data from API! HTTP/%d" % response.status_code)

        _, file_extension = os.path.splitext(country_data['flag_file'])
        dest_filename = "{}/{}{}".format(dest_dir, alpha_2, file_extension)
        if response.headers.get("content-encoding") == "gzip":
            compressed_content = True
        else:
            compressed_content = False
        if compressed_content:
            # Need to access the decoded content bytes.
            # XXX I don't think this BytesIO is very well optimized code.
            with open(dest_filename, "wb") as dest_file:
                with io.BytesIO(response.raw.read(decode_content=True)) as binary_content:
                    shutil.copyfileobj(binary_content, dest_file)
        else:
            # Just stream-copy the bytes:
            with open(dest_filename, "wb") as dest_file:
                shutil.copyfileobj(response.raw, dest_file)
        log.info("Saved {} into {}".format(country_data, dest_filename))
        saved_flag_count += 1

    log.info("Done saving {} flags".format(saved_flag_count))


def main() -> None:
    parser = argparse.ArgumentParser(description='World flags importer')
    parser.add_argument('--destination-dir', metavar="DESTINATION-DIRECTORY",
                        help='Save downloaded files into the directory')
    args = parser.parse_args()
    _setup_logger()

    session = _get_http_client()
    list_of_flags = get_flag_list(session)
    download_flag_list(session, list_of_flags, args.destination_dir)


if __name__ == "__main__":
    main()
