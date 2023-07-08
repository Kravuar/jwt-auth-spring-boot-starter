package net.kravuar.jwtauth;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties("jwt-auth")
@RequiredArgsConstructor
public class JWTAuthProps {
    public final List<String> unauthenticatedServlets;
    public final List<String> corsAllowed;
    public final JWTProps jwt;

    @RequiredArgsConstructor
    public static class JWTProps {
        public String authoritiesClaimName = "authorities";
        public String accessCookieName = "access";
        public String accessCookiePath = "/";
        public String refreshCookieName = "refresh";
        public String refreshCookiePath = "/auth/refresh";
        public long accessTokenExpiration = 300;
        public long refreshTokenExpiration = 43200;
    }
}