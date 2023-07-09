package net.kravuar.jwtauth.components;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt-auth.jwt")
@Setter
@Getter
public class JWTProps {
    private String cookiePrefix = "Bearer_";
    private String issuer = "jwt-auth";
    private String authoritiesClaimName = "authorities";
    private String accessCookieName = "access";
    private String accessCookiePath = "/";
    private String refreshCookieName = "refresh";
    private String refreshCookiePath = "/auth/refresh";
    private long accessTokenExpiration = 300;
    private long refreshTokenExpiration = 43200;
}