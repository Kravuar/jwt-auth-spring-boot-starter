package net.kravuar.jwtauth.components;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

public class JWTAuthFilter extends AbstractAuthenticationProcessingFilter {
    private final String cookieName;

    public JWTAuthFilter(RequestMatcher ignoringMatcher, String cookieName, AuthenticationManager authManager, AuthenticationSuccessHandler authenticationSuccessHandler) {
        super(new NegatedRequestMatcher(ignoringMatcher));
        setAuthenticationSuccessHandler(authenticationSuccessHandler);
        setAuthenticationManager(authManager);
        this.cookieName = cookieName;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        var cookie = WebUtils.getCookie(request, cookieName);
        var jwt = cookie == null
                ? null
                : cookie.getValue();

        var token = new JWTAuthenticationToken(jwt);
        return getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }
}