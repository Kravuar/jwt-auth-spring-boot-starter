package net.kravuar.jwtauth.components;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;

public class JWTAuthFilter extends AbstractAuthenticationProcessingFilter {
    private final Function<HttpServletRequest, String> jwtExtractor;

    public JWTAuthFilter(RequestMatcher ignoringMatcher, AuthenticationManager authManager, Function<HttpServletRequest, String> jwtExtractor) {
        super(new NegatedRequestMatcher(ignoringMatcher), authManager);
        this.jwtExtractor = jwtExtractor;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        var token = new JWTAuthenticationToken(jwtExtractor.apply(request));
        return getAuthenticationManager().authenticate(token);
    }
}