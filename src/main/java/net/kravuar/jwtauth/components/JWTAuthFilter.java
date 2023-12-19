package net.kravuar.jwtauth.components;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JWTAuthFilter extends AbstractAuthenticationProcessingFilter {
    private final JWTExtractor jwtExtractor;

    public  JWTAuthFilter(RequestMatcher ignoringMatcher, AuthenticationManager authManager, JWTExtractor jwtExtractor) {
        super(new NegatedRequestMatcher(ignoringMatcher), authManager);
        this.jwtExtractor = jwtExtractor;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        var token = new JWTAuthenticationToken(jwtExtractor.extract(request));
        return getAuthenticationManager().authenticate(token);
    }
}