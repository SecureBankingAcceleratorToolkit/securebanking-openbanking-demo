import org.forgerock.secrets.keys.SigningKey
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.builders.JwtBuilderFactory
import org.forgerock.secrets.Purpose
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.http.protocol.Status
import org.forgerock.http.protocol.Response

/*
 * Add detached signature to HTTP response
 *
 * Detached signature is signed JWT with response entity as payload
 * JWT is added as response header, with payload removed
 *
 * Can be replaced with JwtBuilderFilter if/when it can be used as a response filter
 *
 */


next.handle(context, request).thenOnResult({ response ->


  JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(routeArgAlgorithm)

  Purpose<SigningKey> purpose = new JsonValue(routeArgSecretId).as(purposeOf(SigningKey.class))

  SigningManager signingManager = new SigningManager(routeArgSecretsProvider)
  signingManager.newSigningHandler(purpose).then({ signingHandler ->

    JwtClaimsSet jwtClaimsSet = new JwtClaimsSet(response.getEntity().getJson())


    String jwt = new JwtBuilderFactory()
            .jws(signingHandler)
            .headers()
            .alg(signAlgorithm)
            .kid(routeArgKid)
            .done()
            .claims(jwtClaimsSet)
            .build()

    logger.debug("Signed JWT [" + jwt + "]")

    if (jwt == null || jwt.length() == 0) {
      logger.error("Error creating signature JWT")
      response = new Response(Status.INTERNAL_SERVER_ERROR)
      return response
    }

    String[] jwtElements = jwt.split("\\.")

    if (jwtElements.length != 3) {
      logger.error("Wrong number of dots on outbound detached signature")
      response = new Response(Status.INTERNAL_SERVER_ERROR)
      return response
    }

    String detachedSig = jwtElements[0] + ".." + jwtElements[2]

    logger.debug("Adding detached signature [" + detachedSig + "]")

    response.getHeaders().add(routeArgHeaderName,detachedSig);


    return response

  })

})