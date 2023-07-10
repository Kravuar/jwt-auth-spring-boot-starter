package net.kravuar.jwtauth.components;

import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;

@RequiredArgsConstructor
public class JWTAuthenticationProvider implements AuthenticationProvider {
    private final JWTUtils jwtUtils;
    private final JWTProps jwtProps;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            JWTAuthenticationToken bearer = (JWTAuthenticationToken) authentication;
            var decodedJWT = jwtUtils.decode(bearer.getJwt());
            var subject = decodedJWT.getSubject();
            var authorities = Arrays.stream(decodedJWT.getClaim(jwtProps.getAuthoritiesClaimName()).asArray(String.class))
                    .map(SimpleGrantedAuthority::new).toList();
            return new JWTAuthenticationToken(bearer.getJwt(), subject, authorities);
        } catch (JWTVerificationException exception) {
            throw new AuthenticationCredentialsNotFoundException(exception.getMessage(), exception);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
