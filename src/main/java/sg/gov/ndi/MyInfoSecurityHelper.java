package sg.gov.ndi;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.RandomStringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.Nonce;


public class MyInfoSecurityHelper {
	

	/**
	 * <p>
	 * get Payload Method
	 * </p>
	 * 
	 * <p>
	 * Decrypt and retrieve payload returned from the Person API call
	 * </p>
	 *
	 * @param result
	 *            the returned encrypted result
	 * @param privateKey
	 *            the private key
	 * @return the decrypted payload
	 * @since 1.0
	 */
	public static String getPayload(String result, ECPrivateKey privateKey) throws MyInfoException {

		
		JWEObject jweObject;
		try {
			// Parse JWE & validate headers
	        jweObject = EncryptedJWT.parse(result);
	        
	        // Set PrivateKey and Decrypt
	        JWEDecrypter decrypter = new ECDHDecrypter(privateKey);
	        jweObject.decrypt(decrypter);
	        
		} catch (Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		// Get String Payload
		String payload = jweObject.getPayload().toString();

		return payload;
	}

	/**
	 * <p>
	 * Verify Token Method
	 * </p>
	 * 
	 * @param decryptedPayload
	 *            the decrypted payload
	 * @param pubKey
	 *            the public key
	 * @return the verified token
	 * @since 1.0
	 */
	public static DecodedJWT verifyToken(String decryptedPayload, RSAPublicKey pubKey) throws MyInfoException {

		DecodedJWT personJWT;

		Algorithm algo = Algorithm.RSA256(pubKey);
		JWTVerifier verifier = JWT.require(algo).acceptLeeway(300).build();

		try {
			personJWT = verifier.verify(decryptedPayload);

		} catch (Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		return personJWT;
	}
	
	/**
	 * <p>
	 * Create code verifier
	 * </p>
	 * 
	 * @return the verifier
	 * @since 1.0
	 */
	public static String createCodeVerifier() throws MyInfoException {
		SecureRandom sr = new SecureRandom();
		byte[] code = new byte[32];
		sr.nextBytes(code);
		String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
		
		return verifier;
	}
	
	/**
	 * <p>
	 * Create code challenge
	 * </p>
	 * 
	 * @param verifier
	 * @return the code challenge
	 * @since 1.0
	 */
	public static String createCodeChallenge(String verifier) throws MyInfoException {
		try {
			byte[] bytes = verifier.getBytes("US-ASCII");
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(bytes, 0, bytes.length);
			byte[] digest = md.digest();
			String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
			
			return challenge;
			
		} catch(Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		
	}
	
	/**
	 * <p>
	 * Verify JSON web token (jwt) using JSON web key (jwk)
	 * </p>
	 * 
	 * @param token
	 * 			a JWT token
	 * @param url 
	 * 			JWKS is a set of keys containing the public keys used to verify any JSON Web Token (JWT).
	 * @return decoded jwt
	 * @since 1.0
	 */
	public static DecodedJWT verifyToken(String token, String url) throws MyInfoException {

		// The URL to the JWKS endpoint
		URL jwksUrl;
		JWSObject jwsObj = null;
		DecodedJWT jwt = null;
		try {
			jwksUrl = new URL(url);

			jwsObj = JWSObject.parse(token);

			// Create a new JWK source with rate limiting and refresh ahead
			// caching, using sensible default settings
			JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl).build();

			JWKMatcher matcher = new JWKMatcher.Builder().keyIDs(jwsObj.getHeader().getKeyID()).build();

			// Will select keys marked for signature use only
			JWKSelector selector = new JWKSelector(matcher);

			// Get the JWK with the ECC public key
			List<JWK> jwk = jwkSource.get(selector, null);

			// Create a JWS verifier from the JWK set source
			JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwsObj.getHeader(),
					jwk.get(0).toECKey().toECPublicKey());

			Boolean flag = false;

			flag = jwsObj.verify(verifier);
			if (!flag) {
				throw new MyInfoException("JWT validation fail.");
			} else {
				jwt = JWT.decode(token);
			}
		} catch (Exception e) {
			throw new MyInfoException(e.getMessage());
		}

		return jwt;
	}
	
	public static ECKey generateEphemeralKeys() throws MyInfoException {
		try {
			
			String kid = RandomStringUtils.randomAlphanumeric(40);
			
		    ECKey jwk = new ECKeyGenerator(Curve.P_256)
		    	    .keyID(kid)
		    	    .generate();
			
			return jwk;
		} catch(Exception e) {
			throw new MyInfoException(e.getMessage());
		}
	}
	
public static String generateDPoP(String url, String method, ECKey sessionPopKeyPair, AccessToken ath, String uuid) throws MyInfoException {
		
		SignedJWT proof = null;
		try {
			Date iat = new Date();
	        JWTID jti = new JWTID(40);        
	        URI uri = new URI(url);       
	        // 2 minutes in milliseconds
	     	long twoMinutesInMillis = 2 * 60 * 1000; 
	     	Date exp = new Date(iat.getTime() + twoMinutesInMillis);
	     	
	     	JWK jwk = sessionPopKeyPair;
	        
	        JOSEObjectType TYPE = new JOSEObjectType("dpop+jwt");
	        
	        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
	    			.type(TYPE)
	    			.jwk(jwk.toPublicJWK())
	    			.build();

	        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
	    			.jwtID(jti.getValue())
	    			.claim("htm", method)
	    			.issueTime(iat)
	    			.expirationTime(exp);
	        
	        if (ath != null) {
	        	uri = new URI(url+"/"+uuid);
				builder = builder.claim("ath", computeSHA256(ath).toString())
						.claim("htu", uri.toString());
			} else {
				builder = builder.claim("htu", uri.toString());
			}
	        
	        JWTClaimsSet jwtClaimsSet = builder.build();
	        
	        DefaultJWSSignerFactory factory = new DefaultJWSSignerFactory();
	        JWSSigner jwsSigner = factory.createJWSSigner(jwk, JWSAlgorithm.ES256);
	        
	        
	        proof = new SignedJWT(jwsHeader, jwtClaimsSet);
	        proof.sign(jwsSigner);
			
		} catch(Exception e) {
			throw new MyInfoException(e.getMessage());
		}
		return proof.serialize();
	}
	
	public static String generateClientAssertion(final String url, final String clientId, Base64URL jktThumbprint, String keyId, ECPrivateKey privateSigningKey)
			throws MyInfoException {
		

		Map<String, Object> cnf = new HashMap<String, Object>();
		cnf.put("jkt", jktThumbprint.toString());
		
		String jwt="";
		try {

			final JWSSigner signer = new ECDSASigner(privateSigningKey, Curve.P_256);
			final SignedJWT signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.ES256)
							.keyID(keyId)
							.type(JOSEObjectType.JWT).build(),
							new JWTClaimsSet.Builder()
							.issuer(clientId)
							.subject(clientId)
							.audience(url)
							.issueTime(new Date())
							.expirationTime(new Date(System.currentTimeMillis() + 300000L))
							.jwtID(new JWTID().getValue())
							.claim("cnf", cnf).build());
			
			signedJWT.sign(signer);

			jwt = signedJWT.serialize();

		} catch (Exception e) {
			e.printStackTrace();
			throw new MyInfoException(e.getMessage());
		}	
		
			
			return jwt;
	}
	
	private static Base64URL computeSHA256(final AccessToken accessToken)
			throws JOSEException {
			
			byte[] hash;
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				hash = md.digest(accessToken.getValue().getBytes(StandardCharsets.UTF_8));
			} catch (NoSuchAlgorithmException e) {
				throw new JOSEException(e.getMessage(), e);
			}
			
			return Base64URL.encode(hash);
		}
		

}
