# BurpJSLinkFinderV2
Burp Extension for passive scanning of JS files to find endpoint links.

![Screenshot](https://github.com/phlmox/BurpJSLinkFinderv2/assets/62145317/f4f61bd9-f25d-445a-b91a-75b851821d5c)

# Installation

1) Go to the Burp Suite Extender Tab -> Click 'Add'.
2) Set Extension Type to Python, then click the 'Select File' button and select `jslinkfinder.py`, and click 'Next'.
3) Done!

# Changelog

## V2.3
- Added 'Referer' tab. Thanks to @Giftedboy

## V2.2
- Updated the regex used for scanning.

## V2.1
- Added 'Delete selected items' feature.

## V2
- Added 'Only scope' feature.
- Replaced Textbox with JTable.
- Added a blacklist filter for various extensions (jpg, png, gif, css, etc.).
- Added 'Export endpoints' feature.

Original repo: https://github.com/InitRoot/BurpJSLinkFinder
