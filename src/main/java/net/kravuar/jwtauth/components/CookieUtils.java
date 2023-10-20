package net.kravuar.jwtauth.components;

import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import net.kravuar.jwtauth.components.props.CookieProps;
import net.kravuar.jwtauth.components.props.JWTProps;

import java.util.List;

@RequiredArgsConstructor
public class CookieUtils {
    private final CookieProps cookieProps;
    private final JWTProps jwtProps;

    public List<Cookie> getJWTCookies(String accessToken, String refreshToken) {
        var refreshCookie = new Cookie(cookieProps.getAccessCookieName(), accessToken);
        refreshCookie.setHttpOnly(cookieProps.getHttpOnly());
        refreshCookie.setMaxAge((int) jwtProps.getRefreshTokenExpiration());
        refreshCookie.setPath(cookieProps.getAccessCookiePath());

        var accessCookie = new Cookie(cookieProps.getRefreshCookieName(), refreshToken);
        accessCookie.setHttpOnly(cookieProps.getHttpOnly());
        accessCookie.setMaxAge((int) jwtProps.getAccessTokenExpiration());
        accessCookie.setPath(cookieProps.getRefreshCookiePath());

        return List.of(accessCookie, refreshCookie);
    }

    public List<Cookie> getDeleteCookies() {
        var refreshCookie = new Cookie(cookieProps.getAccessCookieName(), "deleted");
        refreshCookie.setHttpOnly(cookieProps.getHttpOnly());
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath(cookieProps.getAccessCookiePath());

        var accessCookie = new Cookie(cookieProps.getRefreshCookieName(), "deleted");
        accessCookie.setHttpOnly(cookieProps.getHttpOnly());
        accessCookie.setMaxAge(0);
        accessCookie.setPath(cookieProps.getRefreshCookiePath());
        return List.of(accessCookie, refreshCookie);
    }
}