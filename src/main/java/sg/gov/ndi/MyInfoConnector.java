package sg.gov.ndi;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;

/**
 * <p>
 * This is the main class of the MyInfoConnector
 * </p>
 * <p>
 * This connector aims to simplify consumer’s integration effort with MyInfo by
 * providing an easy to use functions
 * </p>
 * 
 * @see <a href=
 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/introduction"></a>
 * @since 1.0
 */
public class MyInfoConnector {

	private String keyId;
	private String authorizeJWKSUrl;
	private String clientAppId;
	private String clientAppPwd;
	private String redirectUri;
	private String attributes;
	private String tokenURL;
	private String personURL;
	private String proxyTokenURL;
	private String proxyPersonURL;
	private String useProxy;

	private static MyInfoConnector instance;

	// Private constructor to avoid client applications to use constructor
	private MyInfoConnector(String propPath) throws MyInfoException {
		Properties prop = null;
		try (InputStream input = new FileInputStream(propPath)) {
			prop = new Properties();
			prop.load(input);
			load(prop);
		} catch (IOException e) {
			throw new MyInfoException();
		}

	}

	// Return current instance
	public static MyInfoConnector getCurrentInstance() throws MyInfoException {
		if (instance == null) {
			throw new MyInfoException("No instance has been initialized.");
		}
		return instance;
	}

	// Create singleton
	public static MyInfoConnector getInstance(String propPath) throws MyInfoException {
		if (instance == null) {
			instance = new MyInfoConnector(propPath);
		} else {
			throw new MyInfoException("Instance has been initialized. Please get the current instance.");
		}
		return instance;
	}

	/**
	 * <p>
	 * Load Properties File
	 * </p>
	 * <p>
	 * This function loads the properties file into MyInfoConnector class
	 * variables.
	 * </p>
	 * 
	 * @param prop
	 *            the absolute path of the properties file
	 * @since 1.0
	 * @throws MyInfoException
	 */
	private void load(Properties prop) throws MyInfoException {

		if (StringUtil.isEmptyAndNull(prop.getProperty("KEY_ID"))) {
			throw new MyInfoException("Key id not found or empty in properties file!");
		} else {
			this.keyId = prop.getProperty("KEY_ID");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("CLIENT_ID"))) {
			throw new MyInfoException("Client id not found or empty in properties file!");
		} else {
			this.clientAppId = prop.getProperty("CLIENT_ID");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("CLIENT_SECRET"))) {
			throw new MyInfoException("Client secret not found or empty in properties file!");
		} else {
			this.clientAppPwd = prop.getProperty("CLIENT_SECRET");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("MYINFO_JWKS_URL"))) {
			throw new MyInfoException("Authorize JWKS url not found or empty in properties file!");
		} else {
			this.authorizeJWKSUrl = prop.getProperty("MYINFO_JWKS_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("REDIRECT_URL"))) {
			throw new MyInfoException("Redirect url not found or empty in properties file!");
		} else {
			this.redirectUri = prop.getProperty("REDIRECT_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("ATTRIBUTES"))) {
			throw new MyInfoException("Attributes not found or empty in properties file!");
		} else {
			this.attributes = prop.getProperty("ATTRIBUTES");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("TOKEN_URL"))) {
			throw new MyInfoException("Token url not found or empty in properties file!");
		} else {
			this.tokenURL = prop.getProperty("TOKEN_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("PERSON_URL"))) {
			throw new MyInfoException("Person url not found or empty in properties file!");
		} else {
			this.personURL = prop.getProperty("PERSON_URL");
		}
		if (StringUtil.isEmptyAndNull(prop.getProperty("USE_PROXY"))) {
			throw new MyInfoException("Use proxy indicator not found or empty in properties file!");
		} else {
			this.useProxy = prop.getProperty("USE_PROXY");
			if (this.useProxy.equals(ApplicationConstant.YES)) {
				if (StringUtil.isEmptyAndNull(prop.getProperty("PROXY_TOKEN_URL"))) {
					throw new MyInfoException("Proxy token url not found or empty in properties file!");
				} else {
					this.proxyTokenURL = prop.getProperty("PROXY_TOKEN_URL");
				}
				if (StringUtil.isEmptyAndNull(prop.getProperty("PROXY_PERSON_URL"))) {
					throw new MyInfoException("Proxy person url not found or empty in properties file!");
				} else {
					this.proxyPersonURL = prop.getProperty("PROXY_PERSON_URL");
				}
			}
		}
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function takes in all the required variables, invoke the
	 * getAccessToken API to generate the access token. The access token is then
	 * use to invoke the person API to get the Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code
	 * @param verifier
	 *            the state required in token call
	 * @param jwksUrl
	 *            the JSON Web Key Set (JWKS) containing the public keys
	 * @param privateSigningKey
	 *            the private EC signing key
	 * @param encryptionPrivateKey
	 *            the private EC encryption key
	 * @param clientAppId
	 *            the client id
	 * @param clientAppPwd
	 *            the client password
	 * @param redirectUri
	 *            the redirect url
	 * @param attributes
	 *            the attributes
	 * @param keyId
	 *            the key id
	 * @param tokenUrl
	 *            the token url
	 * @param personUrl
	 *            the person url
	 * @param proxyTokenURL
	 *            user provided proxy url
	 * @param proxyPersonURL
	 *            user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getMyInfoPersonData(String authCode, String verifier, String jwksUrl,
			ECPrivateKey privateSigningKey, ECPrivateKey encryptionPrivateKey, String clientAppId, String clientAppPwd, String redirectUri, String attributes,
			String keyId, String tokenURL, String personURL, String proxyTokenURL, String proxyPersonURL, String useProxy)
			throws MyInfoException {

		String result = null;
		String jsonResponse = null;
		
		//Generate Ephemeral keys
		ECKey sessionPopKeyPair = MyInfoSecurityHelper.generateEphemeralKeys();

		// Get access token
		String token = MyInfoConnector.getAccessToken(authCode, verifier, tokenURL, clientAppId, clientAppPwd, redirectUri,
				keyId, privateSigningKey, sessionPopKeyPair, proxyTokenURL, useProxy);
		System.out.println("token: "+token);
		HashMap<String, String> tokenList = new Gson().fromJson(token, new TypeToken<HashMap<String, String>>() {
		}.getType());
		DecodedJWT tokenJWT = MyInfoSecurityHelper.verifyToken(tokenList.get(ApplicationConstant.ACCESS_TOKEN), jwksUrl);

		// Get person
		result = MyInfoConnector.getPersonData(tokenJWT.getSubject(), tokenList.get(ApplicationConstant.ACCESS_TOKEN),
				personURL, clientAppId, attributes, privateSigningKey, sessionPopKeyPair, proxyPersonURL, useProxy);

			try {				
				String payload = MyInfoSecurityHelper.getPayload(result, encryptionPrivateKey);
				DecodedJWT personJWT = MyInfoSecurityHelper.verifyToken(payload, jwksUrl);

				// Convert byte[] to String
				byte[] base64Decode = Base64.getDecoder().decode(personJWT.getPayload());
				jsonResponse = new String(base64Decode);

			} catch (Exception e) {
				e.printStackTrace();
				throw new MyInfoException();
			}

		return jsonResponse;
	}

	/**
	 * <p>
	 * Get MyInfo Person Data
	 * </p>
	 * <p>
	 * This function will retrieve all the properties value from the class
	 * variable and call the static getMyInfoPersonData function to retrieve
	 * MyInfo Person data.
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code (authCode)
	 * @param state
	 *            the state required in token call
	 * @return the person's data in json format.
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/implementation-myinfo-data"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	public String getMyInfoPersonData(String authCode, String verifier, ECPrivateKey privateSigningKey, ECPrivateKey encryptionPrivateKey) throws MyInfoException {
		return getMyInfoPersonData(authCode, verifier, this.authorizeJWKSUrl, privateSigningKey, encryptionPrivateKey, this.clientAppId, this.clientAppPwd, this.redirectUri, this.attributes,
				this.keyId, this.tokenURL, this.personURL, this.proxyTokenURL, this.proxyPersonURL, this.useProxy);
	}


	/**
	 * <p>
	 * Get Authorization(Access) Token
	 * </p>
	 * <p>
	 * This API is invoked by your application server to obtain an "access
	 * token", which can be used to call the Person API for the actual data.
	 * Your application needs to provide a valid "authorisation code" from the
	 * authorise API in exchange for the "access token".
	 * </p>
	 * 
	 * @param authCode
	 *            the authorisation code
	 * @param verifier
	 *            the verifier
	 * @param apiURL
	 *            the api url
	 * @param clientAppId
	 *            the client app id
	 * @param clientAppPwd
	 *            the client secret
	 * @param redirectUri
	 *            the redirect url
	 * @param keyId
	 *            the key id
	 * @param privateSigningKey
	 *            the private signing EC key
	 * @param sessionPopKeyPair
	 *            the session EC key pair
	 * @param proxyTokenURL
	 *            user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the access token
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/oauth"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getAccessToken(String authCode, String verifier, String apiURL, String clientAppId, String clientAppPwd,
			String redirectUri, String keyId, ECPrivateKey privateSigningKey, ECKey sessionPopKeyPair, String proxyTokenURL, String useProxy)
			throws MyInfoException {

		StringBuilder result = new StringBuilder();

		try {
			String cacheCtl = ApplicationConstant.NO_CACHE;
			String method = ApplicationConstant.POST_METHOD;
			int nonceValue = new SecureRandom().nextInt();
			nonceValue = Math.abs(nonceValue);

			String userInputURL = useProxy.equals(ApplicationConstant.YES) ? proxyTokenURL : apiURL;
			
			//Creates new DPoP proof
			String tokendPoP = MyInfoSecurityHelper.generateDPoP(apiURL, ApplicationConstant.POST_METHOD, sessionPopKeyPair, null, null);
			
			//Generate Client Assertions
			Base64URL jktThumbprint = sessionPopKeyPair.toPublicJWK().computeThumbprint("SHA-256");

			String clientAssertion = MyInfoSecurityHelper.generateClientAssertion(apiURL, clientAppId, jktThumbprint, keyId, privateSigningKey);

			// Assembling params for Token API
			StringBuilder params = new StringBuilder();

			params.append(ApplicationConstant.GRANT_TYPE).append("=").append(ApplicationConstant.AUTHORIZATION_CODE)
					.append("&").append(ApplicationConstant.CODE).append("=").append(authCode).append("&")
					.append(ApplicationConstant.REDIRECT_URI).append("=").append(redirectUri).append("&")
					.append(ApplicationConstant.CLIENT_ID).append("=").append(clientAppId).append("&")
					.append(ApplicationConstant.CODE_VERIFIER).append("=").append(verifier).append("&")
					.append(ApplicationConstant.CLIENT_ASSERTION_TYPE).append("=").append(ApplicationConstant.CLIENT_ASSERTION_TYPE_VALUE).append("&")
					.append(ApplicationConstant.CLIENT_ASSERTION).append("=").append(clientAssertion);

			URL url = new URL(userInputURL);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod(method);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setRequestProperty(ApplicationConstant.CONTENT_TYPE, "application/x-www-form-urlencoded");
			conn.setRequestProperty(ApplicationConstant.CACHE_CONTROL, cacheCtl);
			conn.setRequestProperty(ApplicationConstant.DPOP, tokendPoP);

			conn.getOutputStream().write(params.toString().getBytes(StandardCharsets.UTF_8));
			conn.connect();
			int respCode = conn.getResponseCode();
			String respMsg = conn.getResponseMessage();
			if (respCode != 200) {
				throw new IOException("Response Code: " + respCode + "| Response Message: " + respMsg);
			}

			String line = "";

			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}
			reader.close();

		} catch (Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		return result.toString();
	}

	/**
	 * <p>
	 * Get Person Data
	 * </p>
	 * <p>
	 * This method calls the Person API and returns a JSON response with the
	 * personal data that was requested. Your application needs to provide a
	 * valid "access token" in exchange for the JSON data. Once your application
	 * receives this JSON data, you can use this data to populate the online
	 * form on your application.
	 * </p>
	 * 
	 * @param uinFin
	 *            the uinfin no
	 * @param bearer
	 *            the bearer token
	 * @param txnNo
	 *            the transaction no
	 * @param apiURL
	 *            the url api
	 * @param clientAppId
	 *            the client's app id
	 * @param attributes
	 *            the list of requested attributes
	 * @param env
	 *            the the environment
	 * @param myinfoPrivateKey
	 *            the private key
	 * @param proxyPersonURL
	 *            the user provided proxy url
	 * @param useProxy
	 *            indicate the use of proxy url
	 * @return the person data in json
	 * @see <a href=
	 *      "https://www.ndi-api.gov.sg/library/trusted-data/myinfo/oauth"></a>
	 * @since 1.0
	 * @throws MyInfoException
	 */
	protected static String getPersonData(String uinFin, String bearer, String apiURL, String clientAppId,
			String attributes, ECPrivateKey privateSigningKey, ECKey sessionPopKeyPair, String proxyPersonURL, String useProxy)
			throws MyInfoException {
		
		AccessToken ath = new DPoPAccessToken(bearer);
		
		//Creates a new DPoP proof
		String persondPoP = MyInfoSecurityHelper.generateDPoP(apiURL, ApplicationConstant.GET_METHOD, sessionPopKeyPair, ath, uinFin);

		StringBuilder result = new StringBuilder();

		try {

			String userInputURL = (useProxy == ApplicationConstant.YES) ? proxyPersonURL : apiURL;
			userInputURL = userInputURL + "/" + uinFin;

			apiURL = apiURL + "/" + uinFin + "/";

			String cacheCtl = ApplicationConstant.NO_CACHE;
			String method = ApplicationConstant.GET_METHOD;
			int nonceValue = new SecureRandom().nextInt();
			nonceValue = Math.abs(nonceValue);

			// Assembling the params
			StringBuilder params = new StringBuilder();			
			params.append(ApplicationConstant.SCOPE).append("=").append(URLEncoder.encode(attributes, StandardCharsets.UTF_8.toString()));

			userInputURL = userInputURL + "?" + params.toString();
			URL url = new URL(userInputURL);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod(method);
			conn.setDoInput(true);
			conn.setRequestProperty("Cache-Control", cacheCtl);
			conn.setRequestProperty("DPoP", persondPoP);	
			conn.setRequestProperty("Authorization", "DPoP "+bearer);
			conn.connect();
			int respCode = conn.getResponseCode();
			String respMsg = conn.getResponseMessage();

			if (respCode != 200) {
				throw new IOException("Response Code: " + respCode + "| Response Message: " + respMsg);
			}

			String line = "";

			BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			while ((line = reader.readLine()) != null) {
				result.append(line);
			}
			reader.close();

		} catch (Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		return result.toString();
	}

}
