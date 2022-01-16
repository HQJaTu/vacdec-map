# vacdec-map
This repository contains tools for visualizing
a world map with flags of countries using
EU Digital COVID Certificate.

![Map of EU Digital COVID Certificate system member countries](https://blog.hqcodeshop.fi/vacdec-map/map.png)

See also:
* https://github.com/HQJaTu/vacdec
* https://ec.europa.eu/info/live-work-travel-eu/coronavirus-response/safe-covid-19-vaccines-europeans/eu-digital-covid-certificate_en
* https://github.com/eu-digital-green-certificates/

# Workflow

## Update X.509 certificates list
```bash
./cli-utils/fetch-signing-certificates.py
```

## Update flags of countries with certificates into the map
```bash
./cli-utils/embed-flags.py \
    "world-map-with-countries with flags layer.svg" \
    all-flags-directory \
    updated-certs-directory \
    map.svg
```

# Setup

## Dependency libraries

### for Python
```bash
pip install -r requirements.txt
```

### Source SVG map of the world
Download
https://commons.wikimedia.org/wiki/File:Carte_du_monde_vierge_(Allemagnes_séparées).svg

Add layer "Flags" into it.

### Flags of the world
Import flags from https://en.wikipedia.org/wiki/Gallery_of_sovereign_state_flags
```bash
./cli-utils/import-flags.py
```

## PNG output
Tested four different methods, only one is working.
* https://cairosvg.org/
  * Failing to render 100% correct file
* https://github.com/libvips/pyvips
  * Rendering will fail a lot and on multiple ways
* https://github.com/vgalin/html2image
  * Rendering will require Chrome browser
  * Didn't test this properly.
* https://inkscape.org/ on CLI
  * Working perfectly!
  * All fonts are rendered correctly.
  * All flags render correctly.
