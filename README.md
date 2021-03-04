# FIDO2-BiometricJavaCard
The goal of this project was to provide a JavaCard implementation of a biometric FIDO2-Token and evaluate the token regarding FIDO2 certification standards. The underlying hardware of this token is a NFC powered smart card with an integrated fingerprint sensor, also referred as fingerprint card. 

Implementation took place within the scope of my master's thesis with the title <i>"Biometrics-based authentication using WebAuthn"</i> (German) <a href="https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-02/SAR-PR-2020-02_.pdf">[1]</a>. The code published within this repository was only for learning purposes.

&copy; 2019 - 2021, Malte Kruse. This code is published under the GNU GPLv3, for further information see License.txt.

## Code changes
The code was widely left as it was at the time of the master's thesis. Nevertheless, small changes were made. 
This means the HMAC algorithm was re-implemented. Therefore the HMAC class is providing a changed interface, which leads to small changes in the HMAC-usage within the FIDO2Applet class. Some constants were also zeroed out regarding the usage of the biometric sensor. Those constants are specific to the fingerprint card used and therefore not relevant for other smart cards. Lastly, some typos within the comments were fixed.

## How to use this implementation?
According to the specific requirements of the used fingerprint card (biometric sensor integration etc.) the code, as it is, will only be usable with this specific smart card. So the code as published will not work on any other card, unless it is modified to fit the new environment.

Also this implementation does not meet the newest version of the FIDO2 2.0 specification.

## Literature
[1] Kruse, Malte. <i>Biometriebasierte Authentifizierung mit WebAuthn</i>. Humboldt University of Berlin, 2020. [ONLINE]. Available: <a href="https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-02/SAR-PR-2020-02_.pdf">https://sar.informatik.hu-berlin.de/research/publications/SAR-PR-2020-02/SAR-PR-2020-02_.pdf</a>. Last accessed 18 Feb 2021