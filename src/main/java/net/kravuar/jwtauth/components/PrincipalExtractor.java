package net.kravuar.jwtauth.components;

import com.auth0.jwt.interfaces.DecodedJWT;

public interface PrincipalExtractor {

    Object extract(DecodedJWT jwt);
}
