package com.saireddy;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import  io.jsonwebtoken.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.security.Key;
import java.util.Date;


class JsonWebToken {
    private static String SECRET_KEY = "1a4d914c132a239ea0b2147a0c160ef379af634147155ec002f86eb37078f754";

    public static String createJwt() {
        String id = "sai";
        String issuer = "notsai";
        String subject = "maybeSai";
        long timeInMilliSeconds = 3600000; // 60 minutes

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        long currentTime = System.currentTimeMillis();
        Date now = new Date(currentTime);

        byte[] apiSecretKeyBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        Key signingKey = new SecretKeySpec(apiSecretKeyBytes, signatureAlgorithm.getJcaName());

        JwtBuilder builder = Jwts.builder().setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);
        if (timeInMilliSeconds >= 0) {
            long expMillis = currentTime + timeInMilliSeconds;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }
        return builder.compact();
    }

    public static Claims decodeJwt(String jwt) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();
            return claims;
        } catch (JwtException e) {
            throw new RuntimeException("invalid Jwt Token", e);
        }

    }
}

    public class JwtSample{
    public static void main(String[] args) {
        JsonWebToken jsonWebToken = new JsonWebToken();
       String token =  jsonWebToken.createJwt();
        System.out.println(token);
      String  claimsData = String.valueOf(jsonWebToken.decodeJwt(token));
        System.out.println(claimsData);


    }
}
