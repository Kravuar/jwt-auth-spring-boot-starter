package net.kravuar.jwtauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
public class JWTUtils {
    private final Algorithm algorithm;
    private final Props.JWTProps props;

    private Cookie getJWTCookie(User user, String issuer, String cookieName, String path, long expirationTime) {
        var token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date().toInstant().plusSeconds(expirationTime))
                .withIssuer(issuer)
                .withClaim(props.authoritiesClaimName, user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .sign(algorithm);
        var cookie = new Cookie(cookieName, "Bearer " + token);
        cookie.setMaxAge((int) expirationTime);
        cookie.setHttpOnly(true);
        cookie.setPath(path);
        return cookie;
    }
    public List<Cookie> getJWTCookies(User user, String issuer) {
        return List.of(
                getJWTCookie(user, issuer, props.accessCookieName, props.accessCookiePath, props.accessTokenExpiration),
                getJWTCookie(user, issuer, props.refreshCookieName, props.refreshCookiePath, props.refreshTokenExpiration)
        );
    }
    public List<Cookie> getDeleteCookies() {
        var refreshCookie = new Cookie(props.accessCookieName, "deleted");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath(props.accessCookiePath);

        var accessCookie = new Cookie(props.refreshCookieName, "deleted");
        accessCookie.setHttpOnly(true);
        accessCookie.setMaxAge(0);
        accessCookie.setPath(props.refreshCookiePath);
        return List.of(accessCookie, refreshCookie);
    }

    public DecodedJWT decode(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String trimmed = token.substring("Bearer ".length());
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(trimmed);
        } else throw new JWTNotFoundException();
    }
}