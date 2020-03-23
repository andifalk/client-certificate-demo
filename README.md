# Client Certificate Authentication with Spring Boot

## System Requirements

For this tutorial you need the following requirements:

* Java JDK version 11 or newer. Just grab it from [AdoptJDK](https://adoptopenjdk.net/?variant=openjdk11&jvmVariant=hotspot).
* Use a Java IDE of your choice (Just import the repository as a [gradle](https://gradle.org/) project)
* [mkcert](https://mkcert.dev/) to create trusted certificates for localhost. Please follow 
  the [installation instructions](https://github.com/FiloSottile/mkcert#installation) to set this up
  on your machine.
* [Keystore Explorer](https://keystore-explorer.org/) to manage keystore contents. To install it just 
  go to the [Keystore Downloads](https://keystore-explorer.org/downloads.html) page and get the appropriate
  installer for your operating system  
* [httpie](https://httpie.org/), [Curl](https://curl.haxx.se/) or [Postman](https://www.postman.com/) to access the 
server api using a command line or UI client. 
  
## Getting started

To create a local certificate authority (with your own root certificate)
use the following command. Make sure you also have set the _JAVA_HOME_ environment variable if you also want 
to install the root certificate into the trust store of your JDK. 

```
export JAVA_HOME=...
mkcert -install
```

## Setup HTTPS (SSL/TLS) for the application

At first you need a valid trusted server certificate.  
To create a keystore containing the certificate with private/public key pair 
open a command line terminal then navigate to the subdirectory _src/main/resources_ of this project 
and use the following command.

```
mkcert -p12-file server-keystore.p12 -pkcs12 localhost mydev.local
```

Now you should have created a new file _server-keystore.p12_ in the subdirectory _src/main/resources_.

To enable SSL/TLS in the spring boot application add the following entries to the application.properties

```properties
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:server-keystore.p12
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=changeit
server.ssl.key-password=changeit
```


## Setup the client certificate

First we need of course again a valid trusted client certificate to authenticate 
our client at the server.
Open a command line terminal again and navigate to subdirectory _src/main/resources_ of this project
and then use the following command.

```
mkcert -p12-file myuser-client.p12 -client -pkcs12 myuser
```

This file contains the client certificate including the private/public key pair.
To authenticate your web browser for our Spring Boot server application just import
the file _myuser-client.p12_ into the browsers certificate store.

But this is not sufficient, the server application also needs just the certificate (with public key)
to be able to validate the client certificate.
To achieve this we also need to configure a trust keystore for Spring Boot. 
You must not use the keystore we just created because the server should not get access to the private key.

Instead we have to create another keystore using the [Keystore Explorer](https://keystore-explorer.org/)
that only contains the certificate.

But first we have to export the certificate from the existing keystore _myuser-client.p12_:

1. Open keystore with the Keystore Explorer. Select _myuser-client.p12_ in file dialog.
2. Then right click on the single entry and select _Export/Export certificate chain_ and then use the 
   settings as shown in the figure below.
   
![CertExport](images/cert_export.png)   

Now we can import the exported single certificate into a new keystore.

1. Open the explorer and then create a new keystore using the menu _File/New_. 
2. Then chose _PKCS#12_ as type
3. Now select the menu _Tools/Import Trusted Certificate_
4. Select the exported file from previous section
5. Save the keystore as _myuser-trust.p12_ and use password _changeit_ when prompted for

Now let's use this new keystore:

```properties
server.ssl.trust-store=classpath:myuser-trust.p12
server.ssl.trust-store-password=changeit
server.ssl.client-auth=need
```

### Client Test

#### Postman

If you are more into UI based tools then you can use [postman]() to send requests to the server.
Unfortunately postman does not work with self signed certificates with ssl validation turned on.
So open the settings (Menu _File/Settings_), in the _General_ tab deactivate _SSL certificate verification_.

To add the required files for the client certificate authentication just switch to the tab _Certificates_ in the settings dialog.

![PostmanCert](images/postman_certificates.png)

Specify the following settings here:

* Host: localhost:8443
* CRT file: myuser.cer
* KEY file: myuser.pkcs8
* Passphrase: changeit   

Now you can add a new request as shown in the next picture.

![PostmanRequest](images/postman_request.png)

Click the _Send_ button and you should see the expected output.

#### Curl

[Curl](https://curl.haxx.se/) can be configured to connect via a valid secure HTTPS connection and also
authenticating using the client certificate.

Before trying this please make sure that you have imported the CA certificate into the CA store of your operating system
using _mkcert_.

The most easy way for curl to use client certificates is to specify a keystore stored in _PKCS #12_ format.
This way you can hand over the certificate together with the private key to curl at once. In addition to this you need
to specify the password to access the keystore and the private key.

Check out this command for performing access via _curl_:  

```shell script
curl --cert ./src/main/resources/myuser-client.p12:changeit --cert-type p12 -v  https://localhost:8443/api
```

You may also specify the client certificate and the private key separately:

```shell script
curl --cert ./src/main/resources/myuser.cer --cert-type pem --key ./src/main/resources/myuser.pkcs8 --pass changeit  -v  https://localhost:8443/api
```

This should lead to the following output:

```shell script
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: O=mkcert development certificate; OU=afa@t470p (Andreas Falk); CN=localhost
*  start date: Jun  1 00:00:00 2019 GMT
*  expire date: Jan 28 22:12:05 2030 GMT
*  subjectAltName: host "localhost" matched cert's "localhost"
*  issuer: O=mkcert development CA; OU=afa@t470p (Andreas Falk); CN=mkcert afa@t470p (Andreas Falk)
*  SSL certificate verify ok.
* TLSv1.3 (OUT), TLS Unknown, Unknown (23):
> GET /api HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/7.58.0
> Accept: */*
> 
* TLSv1.3 (IN), TLS Unknown, Certificate Status (22):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS Unknown, Unknown (23):
< HTTP/1.1 200 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: text/plain;charset=UTF-8
< Content-Length: 19
< Date: Mon, 23 Mar 2020 20:30:53 GMT
< 
* Connection #0 to host localhost left intact
it works for myuser% 
```

#### Httpie

You can perform the same request to the server using this command with [httpie](https://httpie.org/):

```shell script
http --verbose --cert=./src/main/resources/myuser.cer --cert-key=./src/main/resources/myuser.pkcs8  https://localhost:8443/api
```

Unfortunately you cannot specify the passphrase for the private key (this is a limitation of the python lib used by _httpie_),
so you will get a prompt. Just type _changeit_ and it should run fine.

```shell script
HTTP/1.1 200 
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Connection: keep-alive
Content-Length: 19
Content-Type: text/plain;charset=UTF-8
Date: Mon, 23 Mar 2020 20:21:03 GMT
Expires: 0
Keep-Alive: timeout=60
Pragma: no-cache
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

it works for myuser
```

### Reference Documentation
For further reference, please consider the following sections:

* [Spring Security](https://docs.spring.io/spring-boot/docs/2.2.4.RELEASE/reference/htmlsingle/#boot-features-security)

### Guides
The following guides illustrate how to use some features concretely:

* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)

