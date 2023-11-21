# DeceptorDetector
DeceptorDetector is a (buggy) Burp Suite extension designed to identify and flag potentially vulnerable HTTP responses that are susceptible to cache deception attacks. This tool is essential for security researchers, penetration testers, and web developers aiming to enhance web application security.

## Features
* Sensitive Data Detection: Automatically flags HTTP responses containing sensitive information without proper cache control headers (e.g., 'no-store', 'no-cache').

* Customizable Keyword Scanning: Allows users to define custom keywords for scanning in addition to a predefined list of sensitive data indicators.

* Mark as Tested: Users can mark specific requests as "tested" to filter out from future scans, reducing noise.

* User-Friendly Interface: Integrates seamlessly with Burp Suite, providing an intuitive and efficient user experience.

## Installation

1. **Download Jython**:
   - Download the latest standalone Jython JAR from [Jython Downloads](http://www.jython.org/downloads.html).

2. **Configure Burp Suite**:
   - Open Burp Suite.
   - Navigate to the 'Extender' tab.
   - In the 'Options' sub-tab, under the 'Python Environment' section, select the path to the Jython JAR file you downloaded.

3. **Load DeceptorDetector**:
   - Still in the 'Extender' tab, switch to the 'Extensions' sub-tab.
   - Click 'Add'.
   - Choose 'Python' as the Extension Type.
   - Select the 'DeceptorDetector.py' script file.
   - Click 'Next' to load the extension.

4. **Verify Extension**:
   - Ensure that 'DeceptorDetector' is listed in the extensions table and the status is 'Loaded'.

## Usage
Once installed, DeceptorDetector monitors the traffic passing through Burp Suite. It flags responses that contain sensitive keywords without proper cache-control headers. These flagged entries are displayed in a dedicated tab for further analysis.

* Add Custom Keywords: Enter keywords in the provided text field and click 'Update'.
* Mark as Tested: Right-click on a request in the Burp Suite HTTP history and select 'Mark as Tested' or use the button in the extension tab.
* Viewing Details: Click on a flagged entry to view the full request and response details in the below section.

## Contributing
Contributions to DeceptorDetector are welcome! Please feel free to fork the repository, make your changes, and submit a pull request.

## License
DeceptorDetector is open-source software licensed under the MIT License.





