package net.kravuar.jwtauth.components;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.Cookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Date;
import java.util.List;

public class JWTUtils {
    private final Algorithm algorithm;
    private final JWTProps jwtProps;
    private final JWTVerifier verifier;

    public JWTUtils(Algorithm algorithm, JWTProps jwtProps) {
        this.algorithm = algorithm;
        this.jwtProps = jwtProps;
        this.verifier = JWT.require(algorithm)
                .withIssuer(jwtProps.getIssuer())
                .build();
    }

    protected Cookie getJWTCookie(User user, String cookieName, String path, long expirationTime) {
        var token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date().toInstant().plusSeconds(expirationTime))
                .withIssuer(jwtProps.getIssuer())
                .withClaim(jwtProps.getAuthoritiesClaimName(), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .sign(algorithm);
        var cookie = new Cookie(cookieName, jwtProps.getCookiePrefix() + token);
        cookie.setMaxAge((int) expirationTime);
        cookie.setHttpOnly(true);
        cookie.setPath(path);
        return cookie;
    }

    public List<Cookie> getJWTCookies(User user) {
        return List.of(
                getJWTCookie(user, jwtProps.getAccessCookieName(), jwtProps.getAccessCookiePath(), jwtProps.getAccessTokenExpiration()),
                getJWTCookie(user, jwtProps.getRefreshCookieName(), jwtProps.getRefreshCookiePath(), jwtProps.getRefreshTokenExpiration())
        );
    }

    public List<Cookie> getDeleteCookies() {
        var refreshCookie = new Cookie(jwtProps.getAccessCookieName(), "deleted");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath(jwtProps.getAccessCookiePath());

        var accessCookie = new Cookie(jwtProps.getRefreshCookieName(), "deleted");
        accessCookie.setHttpOnly(true);
        accessCookie.setMaxAge(0);
        accessCookie.setPath(jwtProps.getRefreshCookiePath());
        return List.of(accessCookie, refreshCookie);
    }

    public DecodedJWT decode(String token) {
        if (token != null && token.startsWith(jwtProps.getCookiePrefix())) {
            String trimmed = token.substring(jwtProps.getCookiePrefix().length());
            return verifier.verify(trimmed);
        } else throw new JWTNotFoundException();
    }
}