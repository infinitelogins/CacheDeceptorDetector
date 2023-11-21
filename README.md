# DeceptorDetector
DeceptorDetector is a (buggy) Burp Suite extension designed to identify and flag potentially vulnerable HTTP responses that are susceptible to cache deception attacks. This tool is essential for security researchers, penetration testers, and web developers aiming to enhance web application security.

# Features
* Sensitive Data Detection: Automatically flags HTTP responses containing sensitive information without proper cache control headers (e.g., 'no-store', 'no-cache').

* Customizable Keyword Scanning: Allows users to define custom keywords for scanning in addition to a predefined list of sensitive data indicators.

* Mark as Tested: Users can mark specific requests as "tested" to filter out from future scans, reducing noise.

* User-Friendly Interface: Integrates seamlessly with Burp Suite, providing an intuitive and efficient user experience.

# Installation
1. Download the DeceptorDetector jar file.
1. Open Burp Suite, navigate to the 'Extender' tab.
1. Click on 'Add', and select the downloaded jar file.
1. DeceptorDetector will now be available as a tab within Burp Suite.

# Usage
Add Custom Keywords: Enter keywords in the provided text field and click 'Update'.
Mark as Tested: Right-click on a request in the Burp Suite HTTP history and select 'Mark as Tested' or use the button in the extension tab.
Viewing Details: Click on a flagged entry to view the full request and response details in the below section.

# Contributing
Contributions to DeceptorDetector are welcome! Please feel free to fork the repository, make your changes, and submit a pull request.

# License
DeceptorDetector is open-source software licensed under the MIT License.

