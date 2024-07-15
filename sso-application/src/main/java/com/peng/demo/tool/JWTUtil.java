package com.peng.demo.tool;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.Map;

public class JWTUtil {

    //JWT构成: header, payload, signature
    //token生成
    public static String tokenEncode(String name, String secret, long timeout) {
        //secret  密钥
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + timeout))
                .withClaim("name", name)
                .sign(algorithm);
        return token;
    }

    //token解密
    public static Map<String, Claim> decode(String token, String secret) throws Exception {
        if (token == null || token.length() == 0) {
            throw new Exception();
        }
        Algorithm algorithm = Algorithm.HMAC256(secret);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(token);
        return decodedJWT.getClaims();
    }

}
