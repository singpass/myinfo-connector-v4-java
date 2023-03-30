# MyInfo Connector v4 for Java

MyInfo Connector aims to simplify consumer's integration effort with MyInfo by providing an easy to use Java library to integrate into your application.

## Requirements

Java 1.8 and later

### 1.1 Maven Installation

Add the following to your application's pom.xml

```xml
<dependency>
	<groupId>MyInfoConnector-v4-1.0.jar</groupId>
	<artifactId>MyInfoConnector-v4-1.0.jar</artifactId>
	<scope>system</scope>
	<version>1.0</version>
	<systemPath>${basedir}\src\main\webapp\WEB-INF\lib\MyInfoConnector-v4-1.0.jar</systemPath>
</dependency>
```

### 1.2 Import Connector

Import the MyInfoConnector.java into your code as below:

```java
import sg.gov.ndi.MyInfoConnector;
```

### 1.3 Properties file
You are required to create a properties file with the following properties for this library. Samples of the properties file can be found in this repository under the Sample Properties folder.
| Required Properties | Description |
| -------- | ----------- |
| KEYID | Key id |
| CLIENT_ID | Unique ID provided upon approval of your application to use MyInfo. For our sample application, it is **STG2-MYINFO-SELF-TEST** |
| REDIRECT_URL | The callback URL specified when invoking the authorise call. For our sample application, it is http://localhost:3001/callback |
| ATTRIBUTES | Space separated list of attributes requested. Possible attributes are listed in the Person object definition in the API specifications. |
| TOKEN_URL | Specify the TOKEN API URL for MyInfo. The API is available in three environments:<br> SANDBOX: **https://sandbox.api.myinfo.gov.sg/com/v4/token**<br> TEST: **https://test.api.myinfo.gov.sg/com/v4/token**<br> PROD:  **https://api.myinfo.gov.sg/com/v4/token** |
| PERSON_URL | Specify the TOKEN API URL for MyInfo. The API is available in three environments:<br> SANDBOX: **https://sandbox.api.myinfo.gov.sg/com/v4/person**<br> TEST: **https://test.api.myinfo.gov.sg/com/v4/person**<br> PROD:  **https://api.myinfo.gov.sg/com/v4/person** |
| USE_PROXY | Indicate the use of proxy url. It can be either **Y** or **N**. |
| PROXY_TOKEN_URL | If you are using a proxy url, specify the proxy URL for TOKEN API here. |
| PROXY_PERSON_URL | If you are using a proxy url, specify the proxy URL for PERSON API here. |

## How to use the connector

### 1. Get a single instance of MyInfoConnector

Get a single instance of MyInfoConnector and load properties file:

```
MyInfoConnector connector = MyInfoConnector.getInstance("C:\\MyInfoConnectorPROD.properties");
```

Once the properties file are loaded, you may retrieve the instance again with the below method:
```
MyInfoConnector connector = MyInfoConnector.getCurrentInstance();
```

### 2. Generate Code Verifier and Code Challenge
This method generates the code verifier and the code challenge for the PKCE flow.
```
String verifier = MyInfoSecurityHelper.createCodeVerifier();
```
```
String codeChallenge = MyInfoSecurityHelper.createCodeChallenge(verifier);
```

### 3. Retrieve person's data
Retrieve person's data by passing the authorisation code from the Authorise API call, verifier, (ECPrivateKey) ecPrivateSigningKey and ecPrivateEncryptionKey:

```
connector.getMyInfoPersonData(authCode,verifier,ecPrivateSigningKey,ecPrivateEncryptionKey);
```

## Helper methods

Under the hood, MyInfoConnector make use of **MyInfoSecurityHelper** and you may use the class as util methods to meet your application needs.

### 1. Generating the Demonstration Proof-of-Possession (DPoP)
This method takes in the api url, method and the ephemeral keypair. Additional params (access token and uuid) are needed to generate the DPoP for the Person API call.
https://uat.api.singpass.gov.sg/library/myinfo/developers/dpop
```
MyInfoSecurityHelper.generateDPoP(url,method,sessionPopKeyPair,ath,uuid);
```

### 2. Generating the Client Assertion
This method takes in the api url, client id, jkt thumbprint, keyid and the private signing key.
https://uat.api.singpass.gov.sg/library/myinfo/developers/clientassertion
```
MyInfoSecurityHelper.generateClientAssertion(url,clientAppId,jktThumbprint, keyId,privateSigningKey);
```

### 3. Decrypting and retrieving the Payload
This method takes in the result from the **person** API call and the EC private key to decrypt and retrieve the payload.
```
MyInfoSecurityHelper.getPayload(result, privateKey);
```

### 4. Verify Token
This method takes in the decrypted payload and the url of the JSON Web Key Set (JWKS) .
```
MyInfoSecurityHelper.verifyToken(decryptedPayload, url);
```

## Reporting issues

You may contact [support@myinfo.gov.sg](mailto:support@myinfo.gov.sg) for any other technical issues, and we will respond to you within 5 working days.