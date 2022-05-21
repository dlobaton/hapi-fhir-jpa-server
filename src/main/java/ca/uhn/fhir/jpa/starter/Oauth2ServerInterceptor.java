package ca.uhn.fhir.jpa.starter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.google.gson.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ca.uhn.fhir.rest.api.Constants;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;

import ca.uhn.fhir.rest.server.interceptor.InterceptorAdapter;

public class Oauth2ServerInterceptor extends InterceptorAdapter {

	private int myTimeSkewAllowance = 200;

	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Oauth2ServerInterceptor.class);
	static final RestTemplate restTemplate = new RestTemplate();

	private Set<String> resourceTypes;

	private static Pattern pattern;

	public Oauth2ServerInterceptor(Set<String> resourceTypes) {
		this.resourceTypes = resourceTypes;

		String REGEX = "";

		// Build REGEX
		REGEX = "(?:patient|user)(/)(?:";
		Iterator<String> resourceIterator = this.resourceTypes.iterator();
		while (resourceIterator.hasNext()) {
			REGEX += resourceIterator.next();
			if (resourceIterator.hasNext()) {
				REGEX += "|";
			}
		}
		REGEX += ")(.)(?:read|write)";

		// We compile pattern for REGEX validation of Fhir scopes's syntax
		pattern = Pattern.compile(REGEX);
	}

	public static boolean hasValidFormat(String param) {
		boolean res = false;
		try {
			if (pattern.matcher(param).find()) {
				res = true;
			} else if (param.contains("*")) {
				res = true;
			}
		} catch (Exception e) {
			logger.error("Error matching REGEX");
		}
		return res;
	}

	@Override
	public boolean incomingRequestPostProcessed(RequestDetails theRequestDetails, HttpServletRequest theRequest,
			HttpServletResponse theResponse) throws AuthenticationException {
		String token = theRequest.getHeader(Constants.HEADER_AUTHORIZATION);
		if (token == null) {
			throw new AuthenticationException("Not authorized (no authorization header found in request)");
		}
		if (!token.startsWith(Constants.HEADER_AUTHORIZATION_VALPREFIX_BEARER)) {
			throw new AuthenticationException("Not authorized (authorization header does not contain a bearer token)");
		}

		token = token.substring(Constants.HEADER_AUTHORIZATION_VALPREFIX_BEARER.length());

		// 1. Retrieve introspect token
		SignedJWT idToken;
		JWTClaimsSet idClaims;

		try {
			idToken = SignedJWT.parse(token);
			idClaims = idToken.getJWTClaimsSet(); // here we get introspect claims belonging to a specific user
			logger.info("ID CLAIMS: " + idClaims.toString());
		} catch (ParseException e) {
			throw new AuthenticationException("Not authorized (bearer token could not be validated)", e);
		}

		// 2. Verify signature
		if (!verifySignature(idToken, idClaims)) {
			logger.error("Verification of signature incorrect");
			throw new AuthenticationException("Not authorized (can't determine signature validator)");
		}
		logger.info("Verification of signature CORRECT");

		// 3. Check expiration token
		Calendar expirationTime = Calendar.getInstance();
		expirationTime.setTime(idClaims.getExpirationTime());

		if (expirationTime.getTime() == null) {
			throw new AuthenticationException("Id Token does not have required expiration claim");
		} else {
			// it's not null, see if it's expired
			Calendar nowCalendar = Calendar.getInstance();
			if (expirationTime.getTime().before(nowCalendar.getTime())) {
				throw new AuthenticationException("Id Token is expired: " + expirationTime.getTime());
			}
		}

		// 4. Check not before
		Date notBeforeTime = idClaims.getNotBeforeTime();
		if (notBeforeTime != null) {
			Date now = new Date(System.currentTimeMillis() + (myTimeSkewAllowance * 1000));
			if (now.before(new Date())) {
				throw new AuthenticationException("Id Token not valid untill: " + notBeforeTime.getTime());
			}
		}

		logger.info("Token has not expired");

		// 5. Check issued in the future
		Date issueTime = idClaims.getIssueTime();
		if (issueTime == null) {
			throw new AuthenticationException("Id Token does not have required issued-at claim");
		} else {
			// since it's not null, see if it was issued in the future
			Date now = new Date(System.currentTimeMillis() + (myTimeSkewAllowance * 1000));
			if (now.before(issueTime)) {
				throw new AuthenticationException("Id Token was issued in the future: " + issueTime.getTime());
			}
		}

		// 6. Get the list of scopes from the scope claim from the Access Token
		if (idClaims.getClaim("scope") == null) {
			throw new AuthenticationException("Not authorized (no authorization header found in request)");
		}
		String scopesFromToken[] = idClaims.getClaim("scope").toString().split(" ");

		// 7. If the access token belongs to admin, return true
		if (Arrays.asList(scopesFromToken).contains("system"))
			return true;
		// For the scopes defined as patient/*.* we also need a claim patient from the
		// AT where we find the id from the patient
		JSONArray tokenPatients = (JSONArray) idClaims.getClaim("patient");
		ArrayList<String> patientIds = new ArrayList<String>();
		if (tokenPatients != null) {
			// We load all the patients ids at the patient claim from the AT
			for (Object o : tokenPatients) {
				patientIds.add((String) o);
			}
		}

		// 8. Analyze whether the user's scopes have permissions for the specific
		// request.
		for (String scopeFromToken : scopesFromToken) {
			if (hasValidFormat(scopeFromToken)) {
				String id = scopeFromToken.substring(0, scopeFromToken.indexOf('/'));
				String scopeResource = scopeFromToken.substring(id.length() + 1, scopeFromToken.indexOf('.'));
				String op = scopeFromToken.substring(id.length() + 1 + scopeResource.length() + 1,
						scopeFromToken.length());
				if (scopeFromToken != null) {
					// Checking for the equivalence between HTTP GET, PUT, POST and FHIR Scopes
					// read, write & *
					if (checkOp(theRequestDetails.getRequestType(), op)) {
						// Checking between the requested resource and the defined scope resource
						if (checkResource(theRequestDetails.getResourceName(), scopeResource)) {
							// Checking the level of the scope, between general user scope, or patient
							// limited
							if (id.equals("user")) {
								return true;
							} else if (id.equals("patient")) {
								// When scope defined at patient limited level, and a patient resource is
								// requestedd
								if (theRequestDetails.getResourceName().equals("Patient")) {
									switch (theRequestDetails.getRequestType()) {
									case POST:
									case PUT:
									case DELETE:
										throw new AuthenticationException(
												"Patient user is not allowed to do POST, PUT or DELETE operation.");
									default:
										break;
									}
									if (patientIds.size() > 0) {
										if (theRequestDetails.getId() != null) {
											// Checking that the id request is defined at the patient claim from the AT
											for (int i = 0; i < patientIds.size(); i++) {
												if (patientIds.get(i).contains(theRequestDetails.getId().getValue())) {
													return true;
												}
											}
										}
									} else {
										throw new AuthenticationException(
												"Not authorized. Patient user does not have any resources access right now.");
									}
								}
								throw new AuthenticationException(
										"Not authorized. Insufficient scopes to reach this resource.");
							}
						}
					}
				}
			}
		}
		throw new AuthenticationException("Not authorized");
	}

	private boolean verifySignature(SignedJWT idToken, JWTClaimsSet idClaims) {
		try {
			// 1. Comprobar que hay claim de iss
			String issuerUrl = idClaims.getIssuer();
			if (issuerUrl == null) {
				logger.error("No server configuration found for issuer: " + issuerUrl);
				throw new AuthenticationException(
						"Not authorized (no server configuration found for issuer " + issuerUrl + ")");
			}
			// 2. Comprobar que es un iss valido
			String issuerAsStringObject = restTemplate.getForObject(issuerUrl, String.class);
			JsonObject issuerAsJsonObject = JsonParser.parseString(issuerAsStringObject).getAsJsonObject();
			if (issuerAsJsonObject == null) {
				logger.error("Issuer object is null: " + issuerAsJsonObject);
				throw new AuthenticationException(
						"Not authorized (no issuer json response found for issuerUrl " + issuerUrl + ")");
			}
			// 3. Consultar el header y algoritmo utilizado de encriptación/
			JWSAlgorithm alg = idToken.getHeader().getAlgorithm();
			if (alg.equals(JWSAlgorithm.HS256) || alg.equals(JWSAlgorithm.HS384) || alg.equals(JWSAlgorithm.HS512)) {
				// ToDo
			} else if (alg.equals(JWSAlgorithm.RS256)) { // --- asymmetric
				// 4. Consultar el iss y que tenga un public_key
				String publicKeyAsString = issuerAsJsonObject.get("public_key").getAsString();
				if (publicKeyAsString == null || publicKeyAsString.equals("")) {
					logger.error("Public key for this issuer is null: " + issuerAsStringObject);
					throw new AuthenticationException(
							"Not authorized (no public key found for issuer object " + issuerAsStringObject + ")");
				}
				// 5. Instanciar verifier con la public_key y verificar token
				byte[] buffer = Base64.getDecoder().decode(publicKeyAsString);

				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
				JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyFactory.generatePublic(keySpec));
				return verifier.verify(new JWSHeader(idToken.getHeader().getAlgorithm()), idToken.getSigningInput(),
						idToken.getSignature());
			} else {
				logger.error("Encryption algorithm not contemplated");
				return false;
			}
		} catch (JsonParseException | IllegalStateException e) {
			logger.error("Error: the specified issuer is not valid JSON");
			e.printStackTrace();
		} catch (RestClientException e) {
			logger.error("Error: The configuration request to keycloak server is failing {}", e.getCause());
			throw e;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		return false;

	}

	public boolean checkResource(String reqResource, String scopeResource) {
		if (scopeResource.equals("*")) {
			return true;
		}
		if (reqResource.equals(scopeResource)) {
			return true;
		}
		return false;
	}

	public boolean checkOp(RequestTypeEnum requestTypeEnum, String scopeOp) {
		switch (requestTypeEnum) {
		case GET:
			if (scopeOp.equals("read") || scopeOp.equals("*")) {
				return true;
			}
			break;
		case POST:
			if (scopeOp.equals("write") || scopeOp.equals("*")) {
				return true;
			}
			break;
		case DELETE:
			if (scopeOp.equals("write") || scopeOp.equals("*")) {
				return true;
			}
			break;
		case PUT:
			if (scopeOp.equals("write") || scopeOp.equals("*")) {
				return true;
			}
			break;
		case PATCH:
			if (scopeOp.equals("write") || scopeOp.equals("*")) {
				return true;
			}
			break;
		default:
			break;
		}
		return false;
	}
}