package net.kravuar.jwtauth.components;

import jakarta.servlet.http.HttpServletRequest;

public interface JWTExtractor {
    String extract(HttpServletRequest request);
}
