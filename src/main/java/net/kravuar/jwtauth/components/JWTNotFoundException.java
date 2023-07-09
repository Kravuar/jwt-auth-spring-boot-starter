package net.kravuar.jwtauth.components;

import com.auth0.jwt.exceptions.JWTVerificationException;

public class JWTNotFoundException extends JWTVerificationException {
    public JWTNotFoundException() {
        super("jwtNotFound");
    }
}