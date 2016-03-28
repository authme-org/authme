# AuthMe

AuthMe is a set of programs and services revolving around users authorisating security actions 
from their mobile device.  It comprises:

* A **server component** - currently you need to use the server at 
[www.authme.org](https://www.authme.org/AuthMe).  Eventually this will be provided as a separate package
so you can set up your own server.  The server receives authorisation requests and 
passes them to the mobile device.  It then receives a response that can be picked up by the initial 
requestor.
* A **mobile client** - currently useable on iOS and Android.  This holds the encryption keys and handles 
authorisation requests.
* A **authorisation client** - anything that wants to request an authorisation from the service.  A C 
library has been created to allow others to build their own clients, but currently there is a PAM module 
for *NIX, a command line client (for both Windows and *NIX) and a Windows GUI.

The authorisation client can request the user authorise any action.  As a part of this request, the client 
can provide something that has been previously encrypted and have it decrypted.  The base functionality 
is used for authentication to the PAM module (there is also code for a Spring based J2EE app login).  The 
decryption functionality means the client can encrypt files that can only be decrypted when authorised by 
the mobile device.  This file encryption functionality is available in the command line clients and the
Windows GUI.
