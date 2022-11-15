# uOTP

Simple and secure One Time Password extensions.

## Highlights

uOTP is meant to be:

* secured : using standard crypto API from browser, no 3rd party dependency
* easily auditable : minimal and clean code that can be audit by any programmer
* efficient : no bloat

The main purpose of uOTP is to register several Time-based One-Time Password (TOTP) secret, saving them to be able to generate TOTP codes. Additionally the secrets needs to be encrypted to be securely saved so a main password is required.

Features :

* quick access to registered OTP and clipboard copy on click
* encrypted storage for registered OTP secrets (password needed, not saved in any variable)

Possible futures :

* entry reordering
* mutliple profile (set of OTP saved by a password)

## Architecture

The extension is divided in 2 parts : the main `popup.js` script and a background `background.js` script. The background is used to keep an equivalent of a session and avoid typing the main password everytime the extension is openened.

TOPT algorithm is straightforward and can be done in few lines, the main complexity of the application is the CRUD aspect of the UI and the secured encryption of storage.

The main script and the background communicates through [messages](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Content_scripts#connection-based_messaging) using [runtime.connect()](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/connect).


### background.js

Its only purpose is to keep the encryption key so if the popup is opened it will decrypt the storage content so the content can be read. This key needs the main password to be generated, once this is done the scripts holds the key to be served everytime the popup needs it.

In order to generate the encryption key, `salt` and `iv` are needed. Both needs to be saved in storage, otherwise a generated key from the same password but different iv/salt would not work. Those 2 parameters are bytes array so they are store using Base32 encoding.